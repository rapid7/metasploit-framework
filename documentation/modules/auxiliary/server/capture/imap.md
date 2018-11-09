This module creates a mock IMAP server which accepts credentials.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/imap```
  3. Do: ```run```

## Options

  **BANNER**

  The Banner which should be displayed.  Default is `IMAP4`.
  Some notable banners to emulate:

  * `Dovecot ready.`
  * `IMAP 4 Server (IMail 9.23)`
  * `mailserver Cyrus IMAP4 v2.2.13-Debian-2.2.13-19 server ready`
  * `Welcome to Binc IMAP v1.3.4 Copyright (C) 2002-2005 Andreas Aardal Hanssen at 2018-11-08 11:17:35 +1100`
  * `The Microsoft Exchange IMAP4 service is ready.`
  * `Microsoft Exchange Server 2003 IMAP4rev1 server versino 6.5.7638.1 (domain.local) ready.`

  **SSL**

  Boolean if SSL should be used, making this Secure IMAP.  Secure IMAP is typically run on port 993.  If `SSLCert` is not set, a certificate
  will be automatically generated.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

## Scenarios

### IMAP Emulating Microsoft Exchange with Telnet Client

Server:

```
msf5 > use auxiliary/server/capture/imap 
msf5 auxiliary(server/capture/imap) > set banner "The Microsoft Exchange IMAP4 service is ready."
banner => The Microsoft Exchange IMAP4 service is ready.
msf5 auxiliary(server/capture/imap) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/imap) > 
[*] Started service listener on 0.0.0.0:143 
[*] Server started.
[*] IMAP LOGIN 127.0.0.1:42972 metasploit@documentation.com / rapid7#1
```

Client:

```
root@kali:~# telnet 127.0.0.1 143
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
* OK The Microsoft Exchange IMAP4 service is ready.
01 LOGIN metasploit@documentation.com rapid7#1
quit
Connection closed by foreign host.
```

### Secure IMAP with Self-Signed Certificate and Alpine client

Server:

```
msf5 > openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
[*] exec: openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
.................................................................................................+++++
...................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
msf5 > cat key.pem certificate.pem > selfsigned.pem
[*] exec: cat key.pem certificate.pem > selfsigned.pem

msf5 > cat /root/metasploit-framework/selfsigned.pem
[*] exec: cat /root/metasploit-framework/selfsigned.pem

-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAXME8r2vEUH7B
Kelkt9iC4tTozOq0wJAjsACLCDcNoD4hUH16wy4Uf4SD3ZsEaL0YA0GU2ZgOo2ud
USBpOo8h9FEGtRrAAeSl7Z3XaBnuB7UmVMrnUVZxlaYi84JcopcTOs6KZ5VXddia
PEkE5G3jaCwOIqHk+c8Qk5b43HQbkj2jr4051gHeWP0UgBEy1TVPKtoywtyK1b5H
QhX7MYVNge8lQL/xJnBrjMDqIQqc41lCI73EPCuGZ7zB06xBsgyW/DTgQkprX+Qe
DVKtz8ZChLSqSwmz/5yFttRyZlDuXA7Kozhdj8obRAjzK/gKj89WsX/s2KUbq2GY
pdMpLh7/AgMBAAECggEBALCtQKpdMCzqBdGijgP8u3ZToluDwlprtregco8/51iz
gf0VMXqsg8k96dc3laZyEKNackSlqfxf6npeRdeAenAkNrtjYYNS+c/Qs7Vhntc5
6w6euJHG6g9+9E2LvIMarolx7LvAMbFXwq6+ig5dQ/Sm/DerZWiqbJ18ASDnUhjz
G1Y8/Idy4WutPZD/0JEQ+5VnHb+Mt3a7yYKhDsmUEzVh5xoWJab9dwfwCnoOb32T
oLOLLsqUbAK8ZiQ4MwkbGJ5kw8H24wVmI+7BbuRacW2tIIt6Z+vEoLdof0TsuJWo
87ZbCYYeTysIgBIdLNRiGGxz43SOqBBGh8sreyyACdECgYEA6Ubs1Klw3TViABke
1JqkWelZi6mtsyUHJt/eChjMzgg5vGVuYB/sCc+BObjETbfnvuV0Ub4cxbUCF3wL
qvrJNTd+yU7JJ7IP63B2lS3aNlAsLRb59SkjDYyym1OeUAHKkGp8oICSq96X3Xtu
KUZnDdh2UuoMzmEoAHoDoc+SC/cCgYEA0xmQ+qDJ4l3JRH/IPMPe9XD90WFJFhvF
GzGSM8qqpg6N2xhlzQiM6+I4EEh9iNnCOYmvw9leGNRpIjFjAhv5ntlG3LudAEpd
Ml/hhrfRB7KOopiqzK7oVCUv5f5rmvYdL4c2FC+VGxnhWUP6MARUHag/1DgszMs7
wSlwcbKi8zkCgYBMvRc1khPdwSze6WSZ/dEo/rmFVykb8Idcw3Iwkh31fQE5N4jK
uFWWmJtjGKQDCQeEZckRBuBCLZxli1nvQhakmf/sSy2jEFFqWxG3W2EYUuFlZ9SM
UJ8GWw16SVSf7ybqwQ0EY6dcQJpmsq73hwBprpamCfZygcV9+qVtOnJJ2wKBgBKY
ZPH+6em70zfqfawEoQZD3sfr5vFAnvtHQZa4WpHoJEzReF44S5mXwtKEYDKG5BoH
a+k3o5dSVrSBXzRXXITGpPxatnjJFC6UzZv9YzdnXjMqeZkwKx0GbZK396id13JR
Wc0rZ9oMTJJ9b3N9Xh+Cq6S5EhE0Md5RFSuezcXZAoGBAJOMfjbwobOCYm6K8PyV
p89gbnDOj7FHCg2JPa9/dii6pBRHXeUfORp00GfN0oAjjJo14SmOw58zh1mF1VcA
BQhTK9TO4GXIEZDiYt9EmiH1VO58I8vUecBcbelirumGOP+dBiBy/C8YzFJRhAis
eAGSi8F+qcJaS3VDRGEC9zcK
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUMlkpAG2tXodgLSrIf/xOuA9z8PwwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODExMDkwMTI3MTRaFw0xOTEx
MDkwMTI3MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDAXME8r2vEUH7BKelkt9iC4tTozOq0wJAjsACLCDcN
oD4hUH16wy4Uf4SD3ZsEaL0YA0GU2ZgOo2udUSBpOo8h9FEGtRrAAeSl7Z3XaBnu
B7UmVMrnUVZxlaYi84JcopcTOs6KZ5VXddiaPEkE5G3jaCwOIqHk+c8Qk5b43HQb
kj2jr4051gHeWP0UgBEy1TVPKtoywtyK1b5HQhX7MYVNge8lQL/xJnBrjMDqIQqc
41lCI73EPCuGZ7zB06xBsgyW/DTgQkprX+QeDVKtz8ZChLSqSwmz/5yFttRyZlDu
XA7Kozhdj8obRAjzK/gKj89WsX/s2KUbq2GYpdMpLh7/AgMBAAGjUzBRMB0GA1Ud
DgQWBBRezbFZBumaJ/MViZqqbllYrPomMzAfBgNVHSMEGDAWgBRezbFZBumaJ/MV
iZqqbllYrPomMzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAd
Smkooa2nhdDdu3/uHX8vhDC0ns5qotgd0YKGkj/QyzNP+ruP1cyq/q67zand/Eq8
gF+lHk+pX8GM0WvI7ypgrK956YCdmh3DULBFDu5RxVABFWrGedfNy6TKLTps0PXR
9mdB/HK0Msr6Mh/o5PkUhb1fx0T3NUwF1EFte7Nsq10Mq+hYVnEqDeEGMlb73frJ
729tCjNpFoLGdlgEcAEFelAujV0w4oj35CE2Fh3b+4wupDiulfgg9E7FtvS9xK0P
l/m7Kka0n7lXnKo+IFSJ0dTooBvwaV7+4tEGuHxWJsNO+2aex9qFCuDUdBFxyWyK
uBVlsY6F7EjTfWpxwyVP
-----END CERTIFICATE-----
msf5 > use auxiliary/server/capture/imap 
msf5 auxiliary(server/capture/imap) > set ssl true
ssl => true
msf5 auxiliary(server/capture/imap) > set sslcert /root/metasploit-framework/selfsigned.pem
sslcert => /root/metasploit-framework/selfsigned.pem
msf5 auxiliary(server/capture/imap) > set srvport 993
srvport => 993
msf5 auxiliary(server/capture/imap) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/imap) > 
[*] Started service listener on 0.0.0.0:993 
[*] Server started.
[+] IMAP LOGIN 127.0.0.1:59024 "johndoe" / "p455w0rd"
```

Clients:

```
root@kali:~# cat ~/.muttrc
set spoolfile="imaps://johndoe:p455w0rd@127.0.0.1/INBOX"
set folder="imaps://127.0.0.1/INBOX"
set record="=Sent"
set postponed="=Drafts"

root@kali:~# mutt
```

The user is prompted about the invalid certificate, and the client gets stuck at "Logging in...", however
it doesn't matter since the credentials have already been sent.
