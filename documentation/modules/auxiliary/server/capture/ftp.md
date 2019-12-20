This module creates a mock FTP server which accepts credentials before throwing a `500` error.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/ftp```
  3. Do: ```run```

## Options

  **BANNER**

  The Banner which should be displayed (200 server message).  Default is `FTP Server Ready`.
  Some notable banners to emulate:

  * `Microsoft FTP Service`
  * `ucftpd FTP server ready.`
  * `Serv-U FTP Server v6.4 for WinSock ready...`
  * `Serv-U FTP Server v15.0 ready...`
  * `ProFTPD 1.3.4a Server (FTP-Server)`

  **SSL**

  Boolean if SSL should be used, making this FTPS.  FTPS is typically run on port 990.  If `SSLCert` is not set, a certificate
  will be automatically generated.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

## Scenarios

### FTP Emulating Microsoft with Telnet Client

Server:

```
msf5 > use auxiliary/server/capture/ftp
msf5 auxiliary(server/capture/ftp) > set banner "Microsoft FTP Service"
banner => Microsoft FTP Service
msf5 auxiliary(server/capture/ftp) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/ftp) > 
[*] Started service listener on 0.0.0.0:21 
[*] Server started.
[+] FTP LOGIN 127.0.0.1:44526 root / SuperSecret9
```

Client:

```
root@kali:~# telnet 127.0.0.1 21
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
220 Microsoft FTP Service
USER root
331 User name okay, need password...
PASS SuperSecret9  
500 Error
```

### FTPS with Self-Signed Certificate and curl/lftp Client

Server:

```
msf5 > openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
[*] exec: openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
.................................+++++
........+++++
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
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMboMCNpx4nk16
vx/4gPn7yzMDHh/iTm27gIQKlktxNNKo+I53Cl4vpxLTN4NHxBn47hAlLUm3cADx
j/S9P6f62/GfcKsSeuN7VZ+anRyrdcmsKKenykv3wlfRAR5z7txqiO6LPQpUwiJT
7sgVo8TYRkIIziEXarihk0w1eMKUVlFVR92HFyLaBv0Y1ftCCrZufq6QgStzwjwh
qKFaWXSE3IjYwbVJs03dF2jBVQCVXBj4BTydwYxJ9NrCnwX7BgeRzJWKV+U4akxU
unt5t3/NXJbeTNcHrcvY2CQK4kDhu37xy99jUvOxYxw+8P2HHEgmQWfzHJAJKYCX
wKsFlR53AgMBAAECggEAA0jfSADSoMmCWy+I9vgzjA0mw60PPBaggru842Ko0afU
nqxntZfwDXn0vnoM3PFUrYA9uCszHQRqr3btqsDEFS7FghdQWFqrHwcwKk7N8B9T
XzXEA9knQVLZEF2hPKGg3wFWO9x+NwBrhse2ZUqdVhBC7VtKgtLPJqF0PwOytKlq
/pYniZdkLPrGHcQ13f50vr/dlkIGQ4YaKcAFTjCOxnK7q4of+sa75hFsXVwtnz9j
nw2SEs+SHEfLUl8wPww3IvwCkqFaosagIey2NyTtHxR3lqHobaOmu1nqXkNu/oXk
bt67M3D8VOrKu2aR9sMbirnpjSj+aBSaIjso6kSCaQKBgQD+VdrjMJu3Cr4LSoZL
FV7cog0HBlp3KE910rtY+VHH6c7jo4ow5vVvfITt78/Ntrkj1jAamAV2xA9okMay
7BlL3MVx/MKeQTwEWjTWIed/7Xc5D8o/PqMC8WkIc0Uur3BprwkGTL+wBqo9PHSO
eGo3zcdpbRrL0616o/7+uWIL1QKBgQDNxQq6tBlCY9ckuoof9SmayCmcU4t4Wusx
UJWBN32X8IGVGJRCxMlfwzLUlJwOTIWSkCj6Dw8/njsehda3KgqXbzfemIqD9K+j
/EL/ktrgBmh8ajnjBJX/2O7PsmeF7gFuDjVWflcG6WpuKFapkTsbU4D6ITmLi4uH
0Ot0CMDjGwKBgQCpQrv0XKIUs/p8CzHKgENsdBBVb33/NP2EvSTfdrVdZRXB21GZ
b+tBMc5Jh0J1djhKSD4lRKzGOH7EqS0DYCsJmLhyPrPKnEFz6BCnvVKSiZfBiuef
JXFZAQ5UiFovUqRuQQWxgpxDanwbWsN7GVofHzypxemCYrJeHwwRu5ArrQKBgDpz
FjEip2osYhiUxFd/lGnbIba+JIfzi4tekJk74fke4DAx4yt0Kp+BGxc3f3ywT+Dq
AjnFvVcc4z4wVmWBE7EgboZUXkRNZPb32TAvzuyD5Xox0m+iBdm/DVcCHlX03YMd
lhkTmjTkaM8RtkxEbL2+Yoyqk2YIJYJW3gr/0YqxAoGAe95gaeyjz5IvA/Spfztt
t8Sw0PSNKhw7Th4UwYW1g38Yh/oedHjI/cwV2oegoGRe15nQGQ3IYhyB7yTtsRJI
lVcthX4E1hPRsB3DiuldwWSxJcFhlhm72p/nas/ZsIkE4mKWccj6hJFUlnGhQh+y
dUubf5UfmaGETVVd8MbMNvQ=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUDSznPwoelB25d/7v7bk+mjkDb0kwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODExMDUwMjAxMDVaFw0xOTEx
MDUwMjAxMDVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDMboMCNpx4nk16vx/4gPn7yzMDHh/iTm27gIQKlktx
NNKo+I53Cl4vpxLTN4NHxBn47hAlLUm3cADxj/S9P6f62/GfcKsSeuN7VZ+anRyr
dcmsKKenykv3wlfRAR5z7txqiO6LPQpUwiJT7sgVo8TYRkIIziEXarihk0w1eMKU
VlFVR92HFyLaBv0Y1ftCCrZufq6QgStzwjwhqKFaWXSE3IjYwbVJs03dF2jBVQCV
XBj4BTydwYxJ9NrCnwX7BgeRzJWKV+U4akxUunt5t3/NXJbeTNcHrcvY2CQK4kDh
u37xy99jUvOxYxw+8P2HHEgmQWfzHJAJKYCXwKsFlR53AgMBAAGjUzBRMB0GA1Ud
DgQWBBQzY/telaztoKPEd1vfKqXQ1khMWTAfBgNVHSMEGDAWgBQzY/telaztoKPE
d1vfKqXQ1khMWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAT
ch32xF4s6X4YTg00zbhztiBGxjDDSp6ULk68E6GuxSDcB+wE/nL66urdZJTvlFZk
M26to4odpNhCnYiKIJr4eGvk/8H83yHJn4yr1O2Xy0MJ3piGt4gJm6cA9/DdOzlE
U3tE8X+lcbq4fiz8pkUOU219jiw63OCfB7N1iGMdqCkpLWbGYXH71SAWqzpPFMsA
0oBDYjN1rMBSVA5sFteZNNkidHRE7OaXCAQ20htLZe0cO1rWMO44JKEKalwJW4YZ
n9UgZH3Kq/ptE3Jw6gdj11XT1RSn5NgCutxeCEuPzUhwg3XmVL5fOASJbohQxdGb
mVuIIRbrDW/sOgu2Viis
-----END CERTIFICATE-----

msf5 > use auxiliary/server/capture/ftp
msf5 auxiliary(server/capture/ftp) > set srvport 990
srvport => 990
msf5 auxiliary(server/capture/ftp) > set ssl true
ssl => true
msf5 auxiliary(server/capture/ftp) > set sslcert /root/metasploit-framework/selfsigned.pem
sslcert => /root/metasploit-framework/selfsigned.pem
msf5 auxiliary(server/capture/ftp) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/ftp) > 
[*] Started service listener on 0.0.0.0:990 
[*] Server started.
[+] FTP LOGIN 127.0.0.1:33618 admin / password123
[+] FTP LOGIN 127.0.0.1:33758 admin / password4321
```

Clients:

```
root@kali:~# curl -k --ftp-ssl --user admin:password123 ftps://127.0.0.1:990
curl: (67) Access denied: 500
root@kali:~# lftp ftps://admin:password4321@127.0.0.1:990 -e "set ssl:verify-certificate no; dir;"
ls: Login failed: 500 Error
```
