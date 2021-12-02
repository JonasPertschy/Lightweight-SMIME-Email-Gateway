# Description

This code provides secure e-mail gateway functionality for applications that do not support SMIME encryption + signatures. 
An insecure email is received and protected of sniffing and spoofing. Public keys are obtained via LDAP and the resulting e-mails are compatibel with Outlook/O365.

Why? No of the shell products were available for this scenario and services for secure email gateways are starting at 200 euros per month.



## Flow:
1. Listen on port 2525 for incomming e-mail. 
2. Once an e-mail has been received, obtain the public key of the receiver via LDAP.
3. Encrypt and sign the e-mail.
4. Dispatch the encrypted and signed e-mail to the actual e-mail server.


## Warning:
E-Mail subjects and meta data such as timestamps are not protected via SMIME.

## Credits: 
- [SparkySecure](https://github.com/tuck1s/sparkySecure) - source code is heavily based on "sparkpostSMIME.py"
- [Siemens Issuing CA](https://new.siemens.com/de/de/general/digitales-zertifikat.html)