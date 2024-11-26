## Vulnerable Application

The module uses the Censys REST API to access the same data accessible through
the web interface. The search endpoint allows queries using the Censys Search
Language against the Hosts dataset. Setting the CERTIFICATES option will also
retrieve the certificate details for each relevant service by querying the
Certificates dataset.

## Verification Steps

1. Do: `use auxiliary/gather/censys_search`
1. Do: `set CENSYS_UID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (length: 32 (without dashes))
1. Do: `set CENSYS_SECRET XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` (length: 32)
1. Do: `set CERTIFICATES true` (to get certificates details - optional)
1. Do: `set QUERY <query>`
1. Do: `run`

## Scenarios

A single keyword or a domain name can be used. For advanced searches, the Censys Search Language can also be used.
Here, the following query is used to get the hosts running FTP or Telnet in Germany:
```
location.country_code: DE and services.service_name: {"FTP", "Telnet"}
```

### Without certificates details

```
msf6 auxiliary(gather/censys_search) > run verbose=true QUERY="location.country_code: DE and services.service_name: {"FTP", "Telnet"}" CENSYS_UID=<redacted> CENSYS_SECRET=<redacted>

[+] 2.19.184.189 - 21/FTP,22/SSH,80/HTTP,443/HTTP
[+] 2.19.184.214 - 21/FTP
[+] 2.19.184.216 - 21/FTP
[+] 2.23.14.108 - 21/FTP
[+] 2.23.14.163 - 21/FTP,449/UNKNOWN,515/UNKNOWN,4101/UNKNOWN,4222/UNKNOWN,44100/UNKNOWN,44104/UNKNOWN,44117/UNKNOWN,44133/UNKNOWN,44156/UNKNOWN,44161/UNKNOWN,44162/UNKNOWN,44170/UNKNOWN,44174/UNKNOWN
[+] 2.23.14.195 - 21/FTP,45108/UNKNOWN,45110/UNKNOWN,45111/UNKNOWN,45117/UNKNOWN,45149/UNKNOWN,45150/UNKNOWN,45164/UNKNOWN
[+] 2.23.14.199 - 21/FTP
[+] 2.23.14.201 - 21/FTP,47106/UNKNOWN,47113/UNKNOWN,47150/UNKNOWN
[+] 2.23.14.209 - 21/FTP,49100/UNKNOWN,49121/UNKNOWN,49143/UNKNOWN,49152/UNKNOWN
[+] 2.23.14.212 - 21/FTP
[+] 2.23.14.218 - 21/FTP
[+] 2.23.14.235 - 21/FTP
[+] 2.23.14.243 - 21/FTP
[+] 2.23.15.71 - 21/FTP,22/SSH,80/HTTP,443/HTTP
[+] 2.23.15.238 - 21/FTP,80/HTTP,443/HTTP
[+] 2.56.11.154 - 21/FTP,22/SSH,25/SMTP,53/DNS,80/HTTP,110/POP3,143/IMAP,443/HTTP,465/SMTP,587/SMTP,993/IMAP,2077/HTTP,2078/HTTP,2079/HTTP,2080/HTTP,2082/HTTP,2083/HTTP,2086/HTTP,2087/HTTP,2095/HTTP,2096/HTTP,3306/MYSQL
[+] 2.56.11.222 - 21/FTP,22/SSH,80/HTTP,111/PORTMAP,137/NETBIOS,443/HTTP,445/SMB
[+] 2.56.77.123 - 21/FTP,22/SSH,80/HTTP
[+] 2.56.77.162 - 21/FTP,25/SMTP,80/HTTP,443/HTTP,465/SMTP,587/SMTP,993/IMAP,5022/SSH,8443/HTTP,50080/HTTP
[+] 2.56.77.185 - 21/FTP,25/SMTP,587/SMTP,1024/HTTP,1723/PPTP,4444/UNKNOWN
[+] 2.56.77.186 - 21/FTP,25/SMTP,80/HTTP,443/HTTP,465/SMTP,587/SMTP,1024/HTTP,1723/PPTP,4444/UNKNOWN,5060/SIP
[+] 2.56.77.189 - 21/FTP,25/SMTP,80/HTTP,443/HTTP,465/SMTP,587/SMTP,1024/HTTP,1723/PPTP,4444/HTTP,8080/HTTP,50080/HTTP
...
```

### With certificates details

```
msf6 auxiliary(gather/censys_search) > run verbose=true QUERY="location.country_code: DE and services.service_name: {"FTP", "Telnet"}" CENSYS_UID=<redacted> CENSYS_SECRET=<redacted> CERTIFICATES=true

[+] 2.19.184.189 - 21/FTP,22/SSH,80/HTTP,443/HTTP
[*] Certificate for 21/FTP: C=US, ST=California, L=Mountain View, O=Synopsys\, Inc., CN=eft.synopsys.com (Issuer: C=US, O=Entrust\, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust\, Inc. - for authorized use only, CN=Entrust Certification Authority - L1K)
[*] Certificate for 443/HTTP: C=US, ST=California, L=Mountain View, O=Synopsys\, Inc., CN=eft.synopsys.com (Issuer: C=US, O=Entrust\, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust\, Inc. - for authorized use only, CN=Entrust Certification Authority - L1K)
[+] 2.19.184.214 - 21/FTP
[+] 2.19.184.216 - 21/FTP
[+] 2.23.14.108 - 21/FTP
[+] 2.23.14.163 - 21/FTP,449/UNKNOWN,515/UNKNOWN,4101/UNKNOWN,4222/UNKNOWN,44100/UNKNOWN,44104/UNKNOWN,44117/UNKNOWN,44133/UNKNOWN,44156/UNKNOWN,44161/UNKNOWN,44162/UNKNOWN,44170/UNKNOWN,44174/UNKNOWN
[+] 2.23.14.195 - 21/FTP,45108/UNKNOWN,45110/UNKNOWN,45111/UNKNOWN,45117/UNKNOWN,45149/UNKNOWN,45150/UNKNOWN,45164/UNKNOWN
[+] 2.23.14.199 - 21/FTP
[+] 2.23.14.201 - 21/FTP,47106/UNKNOWN,47113/UNKNOWN,47150/UNKNOWN
[+] 2.23.14.209 - 21/FTP,49100/UNKNOWN,49121/UNKNOWN,49143/UNKNOWN,49152/UNKNOWN
[+] 2.23.14.212 - 21/FTP
[*] Certificate for 21/FTP: C=US, ST=Vermont, L=Colchester, O=VERMONT INFORMATION PROCESSING\, INC., CN=*.vtinfo.com (Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1)
[+] 2.23.14.218 - 21/FTP
[*] Certificate for 21/FTP: C=US, ST=Vermont, L=Colchester, O=VERMONT INFORMATION PROCESSING\, INC., CN=*.vtinfo.com (Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1)
[+] 2.23.14.235 - 21/FTP
[+] 2.23.14.243 - 21/FTP
...

msf6 auxiliary(gather/censys_search) > services
Services
========

host          port   proto  name     state  info
----          ----   -----  ----     -----  ----
2.19.184.189  80     tcp    http     open
2.19.184.189  443    tcp    http     open   C=US, ST=California, L=Mountain View, O=Synopsys\, Inc., CN=eft.synopsys.com (Issuer: C=US, O=Entrust\, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust\, Inc. - for authorized use only, CN=Entrust Certification A
                                            uthority - L1K)
2.19.184.189  21     tcp    ftp      open   C=US, ST=California, L=Mountain View, O=Synopsys\, Inc., CN=eft.synopsys.com (Issuer: C=US, O=Entrust\, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust\, Inc. - for authorized use only, CN=Entrust Certification A
                                            uthority - L1K)
2.19.184.189  22     tcp    ssh      open
2.19.184.214  21     tcp    ftp      open
2.19.184.216  21     tcp    ftp      open
2.23.14.108   21     tcp    ftp      open
2.23.14.163   21     tcp    ftp      open
2.23.14.163   44174  tcp    unknown  open
2.23.14.163   449    tcp    unknown  open
2.23.14.163   515    tcp    unknown  open
2.23.14.163   4101   tcp    unknown  open
2.23.14.163   4222   tcp    unknown  open
2.23.14.163   44104  tcp    unknown  open
2.23.14.163   44100  tcp    unknown  open
2.23.14.163   44117  tcp    unknown  open
2.23.14.163   44133  tcp    unknown  open
2.23.14.163   44156  tcp    unknown  open
2.23.14.163   44161  tcp    unknown  open
2.23.14.163   44162  tcp    unknown  open
2.23.14.163   44170  tcp    unknown  open
2.23.14.195   45108  tcp    unknown  open
2.23.14.195   45111  tcp    unknown  open
2.23.14.195   45164  tcp    unknown  open
2.23.14.195   45150  tcp    unknown  open
2.23.14.195   45149  tcp    unknown  open
2.23.14.195   21     tcp    ftp      open
2.23.14.195   45117  tcp    unknown  open
2.23.14.195   45110  tcp    unknown  open
2.23.14.199   21     tcp    ftp      open
2.23.14.201   47113  tcp    unknown  open
2.23.14.201   21     tcp    ftp      open
2.23.14.201   47106  tcp    unknown  open
2.23.14.201   47150  tcp    unknown  open
2.23.14.209   49100  tcp    unknown  open
2.23.14.209   21     tcp    ftp      open
2.23.14.209   49143  tcp    unknown  open
2.23.14.209   49121  tcp    unknown  open
2.23.14.209   49152  tcp    unknown  open
2.23.14.212   21     tcp    ftp      open   C=US, ST=Vermont, L=Colchester, O=VERMONT INFORMATION PROCESSING\, INC., CN=*.vtinfo.com (Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1)
2.23.14.218   21     tcp    ftp      open   C=US, ST=Vermont, L=Colchester, O=VERMONT INFORMATION PROCESSING\, INC., CN=*.vtinfo.com (Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1)
2.23.14.235   21     tcp    ftp      open
2.23.14.243   21     tcp    ftp      open
```
