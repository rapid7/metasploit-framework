## Vulnerable Application

### Description
Check if a server supports a given version of SSL/TLS and cipher suites.

The certificate is stored in loot, and any known vulnerabilities against that
SSL version and cipher suite combination are checked. These checks include
POODLE, deprecated protocols, expired/not valid certs, low key strength, null cipher suites,
certificates signed with MD5, DROWN, RC4 ciphers, exportable ciphers, LOGJAM, and BEAST.

## Options

### SSLVersion

Which SSL/TLS Version to use. `all` implies all SSL/TLS versions which are usable by the metasploit + ruby + OpenSSL
versions installed on the system. List is dynamically generated. Defaults to `all`

### SSLCipher

Which SSL/TLS Cipher to use. `all` implies all ciphers available for the version of SSL/TLS being used and which
are usable by the metasploit + ruby + OpenSSL versions installed on the system.
List is dynamically generated. Defaults to `all`

## Verification Steps

1. Do: `use auxiliary/scanner/ssl/ssl_version`
2. Do: `set RHOSTS [IP]`
3. Do: `set THREADS [num of threads]`
4. Do: `run`

## Scenarios

### No issues found

An example run against `google.com`, no real issues as expected.

```
msf6 > use auxiliary/scanner/ssl/ssl_version
msf6 auxiliary(scanner/ssl/ssl_version) > set RHOSTS 172.217.12.238
RHOSTS => 172.217.12.238
msf6 auxiliary(scanner/ssl/ssl_version) > run

[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384
[+] 172.217.12.238:443    - Certificate saved to loot: /home/gwillcox/.msf4/loot/20221107150747_default_172.217.12.238_ssl.certificate_342145.txt
[*] 172.217.12.238:443    - Certificate Information:
[*] 172.217.12.238:443    -   Subject: /CN=*.google.com
[*] 172.217.12.238:443    -   Issuer: /C=US/O=Google Trust Services LLC/CN=GTS CA 1C3
[*] 172.217.12.238:443    -   Signature Alg: sha256WithRSAEncryption
[*] 172.217.12.238:443    -   Public Key Size: 2048 bits
[*] 172.217.12.238:443    -   Not Valid Before: 2022-10-17 08:16:43 UTC
[*] 172.217.12.238:443    -   Not Valid After: 2023-01-09 08:16:42 UTC
[*] 172.217.12.238:443    -   CA Issuer: http://pki.goog/repo/certs/gts1c3.der
[*] 172.217.12.238:443    -   Has common name *.google.com
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-CHACHA20-POLY1305
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES128-GCM-SHA256
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: AES256-GCM-SHA384
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: AES128-GCM-SHA256
[*] 172.217.12.238:443    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssl/ssl_version) > show options

Module options (auxiliary/scanner/ssl/ssl_version):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   RHOSTS      172.217.12.238   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       443              yes       The target port (TCP)
   SSLCipher   All              yes       SSL cipher to test (Accepted: All, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-A
                                          ES256-GCM-SHA384, DHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, DHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-
                                          SHA256, ECDHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, DHE-RSA-AES256-SHA256, ECDHE-ECDSA-AES1
                                          28-SHA256, ECDHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA256, ECDHE-ECDSA-AES256-SHA, ECDHE-RSA-AES256-SHA, DHE-RSA-AES256-SHA, ECDHE-ECDSA-AES128-SHA, ECDHE-
                                          RSA-AES128-SHA, DHE-RSA-AES128-SHA, RSA-PSK-AES256-GCM-SHA384, DHE-PSK-AES256-GCM-SHA384, RSA-PSK-CHACHA20-POLY1305, DHE-PSK-CHACHA20-POLY1305, ECDHE-PSK-C
                                          HACHA20-POLY1305, AES256-GCM-SHA384, PSK-AES256-GCM-SHA384, PSK-CHACHA20-POLY1305, RSA-PSK-AES128-GCM-SHA256, DHE-PSK-AES128-GCM-SHA256, AES128-GCM-SHA256,
                                           PSK-AES128-GCM-SHA256, AES256-SHA256, AES128-SHA256, ECDHE-PSK-AES256-CBC-SHA384, ECDHE-PSK-AES256-CBC-SHA, SRP-RSA-AES-256-CBC-SHA, SRP-AES-256-CBC-SHA,
                                          RSA-PSK-AES256-CBC-SHA384, DHE-PSK-AES256-CBC-SHA384, RSA-PSK-AES256-CBC-SHA, DHE-PSK-AES256-CBC-SHA, AES256-SHA, PSK-AES256-CBC-SHA384, PSK-AES256-CBC-SHA
                                          , ECDHE-PSK-AES128-CBC-SHA256, ECDHE-PSK-AES128-CBC-SHA, SRP-RSA-AES-128-CBC-SHA, SRP-AES-128-CBC-SHA, RSA-PSK-AES128-CBC-SHA256, DHE-PSK-AES128-CBC-SHA256
                                          , RSA-PSK-AES128-CBC-SHA, DHE-PSK-AES128-CBC-SHA, AES128-SHA, PSK-AES128-CBC-SHA256, PSK-AES128-CBC-SHA)
   SSLVersion  All              yes       SSL version to test (Accepted: All, SSLv3, TLSv1.0, TLSv1.2, TLSv1.3)
   THREADS     1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/ssl/ssl_version) >
```

### Expired certificate

```
msf6 > use auxiliary/scanner/ssl/ssl_version
msf6 auxiliary(scanner/ssl/ssl_version) > set RHOSTS expired.badssl.com
RHOSTS => expired.badssl.com
msf6 auxiliary(scanner/ssl/ssl_version) > run

[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384
[+] 104.154.89.105:443    - Certificate saved to loot: /home/gwillcox/.msf4/loot/20221107150939_default_104.154.89.105_ssl.certificate_786557.txt
[*] 104.154.89.105:443    - Certificate Information:
[*] 104.154.89.105:443    -   Subject: /C=US/ST=California/L=San Francisco/O=BadSSL Fallback. Unknown subdomain or no SNI./CN=badssl-fallback-unknown-subdomain-or-no-sni
[*] 104.154.89.105:443    -   Issuer: /C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Intermediate Certificate Authority
[*] 104.154.89.105:443    -   Signature Alg: sha256WithRSAEncryption
[*] 104.154.89.105:443    -   Public Key Size: 2048 bits
[*] 104.154.89.105:443    -   Not Valid Before: 2016-08-08 21:17:05 UTC
[*] 104.154.89.105:443    -   Not Valid After: 2018-08-08 21:17:05 UTC
[+] 104.154.89.105:443    -   Certificate contains no CA Issuers extension... possible self signed certificate
[*] 104.154.89.105:443    -   Has common name badssl-fallback-unknown-subdomain-or-no-sni
[+] 104.154.89.105:443    - Certificate expired: 2018-08-08 21:17:05 UTC
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES256-GCM-SHA384
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES128-GCM-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES128-GCM-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES256-SHA384
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES256-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES128-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES128-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: AES256-GCM-SHA384
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: AES128-GCM-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: AES256-SHA256
[+] 104.154.89.105:443    - Connected with SSL Version: TLSv1.2, Cipher: AES128-SHA256
[*] expired.badssl.com:443 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssl/ssl_version) > show options

Module options (auxiliary/scanner/ssl/ssl_version):

   Name        Current Setting     Required  Description
   ----        ---------------     --------  -----------
   RHOSTS      expired.badssl.com  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       443                 yes       The target port (TCP)
   SSLCipher   All                 yes       SSL cipher to test (Accepted: All, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RS
                                             A-AES256-GCM-SHA384, DHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, DHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES12
                                             8-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, DHE-RSA-AES256-SHA256, ECDHE-E
                                             CDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA256, ECDHE-ECDSA-AES256-SHA, ECDHE-RSA-AES256-SHA, DHE-RSA-AES256-SHA, ECDHE-ECDSA-AES128
                                             -SHA, ECDHE-RSA-AES128-SHA, DHE-RSA-AES128-SHA, RSA-PSK-AES256-GCM-SHA384, DHE-PSK-AES256-GCM-SHA384, RSA-PSK-CHACHA20-POLY1305, DHE-PSK-CHACHA20-POLY13
                                             05, ECDHE-PSK-CHACHA20-POLY1305, AES256-GCM-SHA384, PSK-AES256-GCM-SHA384, PSK-CHACHA20-POLY1305, RSA-PSK-AES128-GCM-SHA256, DHE-PSK-AES128-GCM-SHA256,
                                             AES128-GCM-SHA256, PSK-AES128-GCM-SHA256, AES256-SHA256, AES128-SHA256, ECDHE-PSK-AES256-CBC-SHA384, ECDHE-PSK-AES256-CBC-SHA, SRP-RSA-AES-256-CBC-SHA,
                                             SRP-AES-256-CBC-SHA, RSA-PSK-AES256-CBC-SHA384, DHE-PSK-AES256-CBC-SHA384, RSA-PSK-AES256-CBC-SHA, DHE-PSK-AES256-CBC-SHA, AES256-SHA, PSK-AES256-CBC-SH
                                             A384, PSK-AES256-CBC-SHA, ECDHE-PSK-AES128-CBC-SHA256, ECDHE-PSK-AES128-CBC-SHA, SRP-RSA-AES-128-CBC-SHA, SRP-AES-128-CBC-SHA, RSA-PSK-AES128-CBC-SHA256
                                             , DHE-PSK-AES128-CBC-SHA256, RSA-PSK-AES128-CBC-SHA, DHE-PSK-AES128-CBC-SHA, AES128-SHA, PSK-AES128-CBC-SHA256, PSK-AES128-CBC-SHA)
   SSLVersion  All                 yes       SSL version to test (Accepted: All, SSLv3, TLSv1.0, TLSv1.2, TLSv1.3)
   THREADS     1                   yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/ssl/ssl_version) >
```
