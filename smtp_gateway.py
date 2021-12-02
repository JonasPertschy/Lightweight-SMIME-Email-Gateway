from datetime import datetime
import asyncore
from smtpd import SMTPServer
#Key lookup
import ldap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
#Encrypt and sign
import email
import base64
import smime
from email.utils import parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from OpenSSL import crypto
from copy import deepcopy
#SEND MESSAGE
import smtplib


#Encrypt and sign
PKCS7_NOSIGS = 0x4  # defined in pkcs7.h
PKCS7_DETACHED=0x40
def create_embedded_pkcs7_signature(data, cert, key, pkcs7_option):
    """
    Creates an pkcs7 signature.
    For PKCS7_OPT == PKCS7_NOSIGS: equivalent to the output of `openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data`
    Thanks to https://stackoverflow.com/a/47098879/8545455
    For PKCS7_OPT == PKCS7_DETACHED: equivalent to the output of `openssl smime -sign -signer cert -inkey key -outform DER < data`
    :type data: bytes
    :type cert: str
    :type key: bytes
    :type pkcs7_option: int
    """
    assert isinstance(data, bytes)
    assert isinstance(cert, str)
    assert isinstance(key, str)
    try:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        signcert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    except crypto.Error as e:
        raise ValueError('Certificates files are invalid') from e

    bio_in = crypto._new_mem_buf(data)
    pkcs7 = crypto._lib.PKCS7_sign(signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, pkcs7_option)
    bio_out = crypto._new_mem_buf()
    crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
    signed_data = crypto._bio_to_string(bio_out)
    return signed_data


def signEmailFrom(msg, pubcert, privkey, sign_detached=False):
    assert isinstance(msg, email.message.Message)
    assert isinstance(pubcert, str)
    assert isinstance(privkey, str)
    assert isinstance(sign_detached, bool)
    if sign_detached:
        # Need to fix up the header order and formatting here
        rawMsg = msg.as_bytes()
        sgn = create_embedded_pkcs7_signature(rawMsg, pubcert, privkey, PKCS7_DETACHED)
        # Wrap message with multipart/signed header
        msg2 = MIMEMultipart() # this makes a new boundary
        bound = msg2.get_boundary() # keep for later as we have to rewrite the header
        msg2.set_default_type('multipart/signed')
        copyHeaders(msg, msg2)
        del msg2['Content-Language'] # These don't apply to multipart/signed
        del msg2['Content-Transfer-Encoding']
        msg2.attach(msg)
        sgn_part = MIMEApplication(sgn, 'x-pkcs7-signature; name="smime.p7s"', _encoder=email.encoders.encode_base64)
        sgn_part.add_header('Content-Disposition', 'attachment; filename="smime.p7s"')
        msg2.attach(sgn_part)
        # Fix up Content-Type headers, as default class methods don't allow passing in protocol etc.
        msg2.replace_header('Content-Type', 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="{}"'.format(bound))
        return msg2

    else:
        rawMsg = msg.as_bytes()
        sgn = create_embedded_pkcs7_signature(rawMsg, pubcert, privkey, PKCS7_NOSIGS)
        msg.set_payload(base64.encodebytes(sgn))
        hdrList = {
            'Content-Type': 'application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"',
            'Content-Transfer-Encoding': 'base64',
            'Content-Disposition': 'attachment; filename="smime.p7m"'
        }
        copyHeaders(hdrList, msg)
        return msg


def fixTextPlainParts(msg):
    assert isinstance(msg, email.message.Message)
    if msg.is_multipart():
        parts = msg.get_payload()
        for i in range(len(parts)):
            q = fixTextPlainParts(parts[i])
            msg._payload[i] = q
        return msg
    elif msg.get_content_type() == 'text/plain':
        txt = msg.get_payload()
        m = MIMEText(txt, _charset='utf-8')
        return m
    else:
        return msg


def copyHeaders(m1, m2):
    for i in m1.items():
        if m2.get(i[0]):
            m2.replace_header(i[0], i[1])
        else:
            m2.add_header(i[0], i[1])


def copyPayload(m1, m2):
    assert isinstance(m1, email.message.Message)
    assert isinstance(m2, email.message.Message)
    m2._payload = m1._payload


def buildSMIMEemail(msg, encrypt=False, sign=False, sign_detached=False, r_cert=None, s_pubcert=None, s_privkey=None):
    """
    Build SMIME email, given a message file in RFC822 format. Options to encrypt and sign (and sign_detached).
    For encryption, which is retrieved via keylookup().
    For signing, requires sender's public key cert and private key.
    :type msg: email.message.Message
    """
    assert isinstance(msg, email.message.Message)
    msg2 = deepcopy(msg)                # don't overwrite input object as we work on it
    body = fixTextPlainParts(msg2)      # ensure any text/plain parts are base64, block ciphers seem to require it
    copyPayload(body, msg2)
    copyHeaders(body, msg2)
    msg2.__delitem__('Bcc')             # always remove these from the delivered message

    # Sign the message, replacing it in-situ
    if sign or sign_detached:
        msg2 = signEmailFrom(msg2, s_pubcert, s_privkey, sign_detached = sign_detached)
        if msg2==None:
            return None                 # failure, exit early
    # Encrypt the message, replacing it in-situ
    if encrypt:
        msg2 = smime.encrypt(msg2, r_cert)
        # could be valid message or None if an operation failed
    return msg2

#Key lookup
def keylookup(email):
    try:
        con = ldap.initialize('ldap://egress-router:389')
        der_cert = (con.search_s('o=trustcenter',ldap.SCOPE_SUBTREE,'(mail='+email+')',['userCertificate;binary'])[0][1])
        der_cert = der_cert.get("userCertificate;binary")[0]
        certificate = x509.load_der_x509_certificate(der_cert,default_backend())
        crt = certificate.public_bytes(serialization.Encoding.PEM)
        return crt
    except:
        return False



#Read Key Material
with open('[REDACTED].crt', 'r') as cert_fp:
    s_pubcert = cert_fp.read()

with open('[REDACTED].pem', 'r') as key_fp:
    s_privkey = key_fp.read()

encrypt = True
sign = True
sign_detached = False


class EmlServer(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, email_msg, mail_options=None,rcpt_options=None):
        for receipient in rcpttos:
            print('peer',peer)
            print('mailfrom',mailfrom)
            print('receipient',receipient)
            receipient_public_key = keylookup(receipient)
            if receipient_public_key:
                print('data',email_msg)
                email_msg = email.message_from_bytes(email_msg)
                encryptedmessage = buildSMIMEemail(email_msg, encrypt, sign, sign_detached, receipient_public_key, s_pubcert, s_privkey)
                print(encryptedmessage)
                server = smtplib.SMTP("mail", 25)
                server.ehlo()
                server.starttls()
                server.sendmail("[REDACTED]", receipient, encryptedmessage.as_string())
                server.close()
            else:
                #OPTIONAL - INSECURE WARNING. Send unencrypted without signature if no key was found. (Fallback)
                server = smtplib.SMTP("mail", 25)
                server.ehlo()
                server.starttls()
                server.sendmail("[REDACTED]", receipient, email_msg)
                server.close()


def run():
    foo = EmlServer(('0.0.0.0', 2525), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass
    except:
        print("Unexpected error:", sys.exc_info()[0])
        pass

if __name__ == '__main__':
        run()