message = [
    'To: "Jonas Pertschy" <jonas.pertschy@domain.com>',
    'From: "sender@domain.com" <sender@domain.com>',
    'Subject: Docker Test',
    '',
    'Now you see me POC1 without signature.'
]

## SMTPLIB PART
import smtplib
server = smtplib.SMTP("localhost", 2525)
server.ehlo()
server.sendmail("sender@domain.com", "receiver@domain.com", '\n'.join(message))
server.close()


#openssl x509 -inform DER -in jonas.cer -out jonas.crt
#openssl x509 -in jonas.crt -text