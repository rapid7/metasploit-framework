## Vulnerable Application

### Description
Check if a server supports a given version of SSL/TLS and cipher suites.

The certificate is stored in loot, and any known vulnerabilities against that
SSL version and cipher suite combination are checked. These checks include
POODLE, deprecated protocols, expired/not valid certs, low key strength, null cipher suites,
certificates signed with MD5, DROWN, RC4 ciphers, exportable ciphers, LOGJAM, and BEAST.

## Options

## Verification Steps

1. Do: `use auxiliary/scanner/ssl/ssl_version`
2. Do: `set RHOSTS [IP]`
3. Do: `set THREADS [num of threads]`
4. Do: `run`

## Scenarios

### No issues found

An example run against `google.com`, no real issues as expected.

```
resource (ssl_cert.rb)> use auxiliary/scanner/ssl/ssl_version
resource (ssl_cert.rb)> set rhosts 172.217.12.238
rhosts => 172.217.12.238
resource (ssl_cert.rb)> run
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384
[+] 172.217.12.238:443    - Certificate saved to loot: /root/.msf4/loot/20221016163908_default_172.217.12.238_ssl.certificate_484658.txt
[*] 172.217.12.238:443    - Certificate Information:
[*] 172.217.12.238:443    -     Subject: /CN=*.google.com
[*] 172.217.12.238:443    -     Issuer: /C=US/O=Google Trust Services LLC/CN=GTS CA 1C3
[*] 172.217.12.238:443    -     Signature Alg: sha256WithRSAEncryption
[*] 172.217.12.238:443    -     Public Key Size: 2048 bits
[*] 172.217.12.238:443    -     Not Valid Before: 2022-09-12 08:16:59 UTC
[*] 172.217.12.238:443    -     Not Valid After: 2022-12-05 08:16:58 UTC
[*] 172.217.12.238:443    -     Has common name *.google.com
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-CHACHA20-POLY1305
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES128-GCM-SHA256
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: AES256-GCM-SHA384
[+] 172.217.12.238:443    - Connected with SSL Version: TLSv1.2, Cipher: AES128-GCM-SHA256
[*] 172.217.12.238:443    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Expired certificate

```
msf6 auxiliary(scanner/ssl/ssl_version) > set rhosts 2.2.2.2
rhosts => 2.2.2.2
msf6 auxiliary(scanner/ssl/ssl_version) > run

[+] 2.2.2.2:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384
[+] 2.2.2.2:443    - Certificate saved to loot: /root/.msf4/loot/20221016165242_default_2.2.2.2_ssl.certificate_176809.txt
[*] 2.2.2.2:443    - Certificate Information:
[*] 2.2.2.2:443    -     Subject: example
[*] 2.2.2.2:443    -     Issuer: example
[*] 2.2.2.2:443    -     Signature Alg: sha256WithRSAEncryption
[*] 2.2.2.2:443    -     Public Key Size: 2048 bits
[*] 2.2.2.2:443    -     Not Valid Before: 2021-06-14 00:00:00 UTC
[*] 2.2.2.2:443    -     Not Valid After: 2022-07-15 23:59:59 UTC
[*] 2.2.2.2:443    -     Has common name example
[+] 2.2.2.2:443    - Certificate expired: 2022-07-15 23:59:59 UTC
[+] 2.2.2.2:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES256-GCM-SHA384
[+] 2.2.2.2:443    - Connected with SSL Version: TLSv1.2, Cipher: ECDHE-RSA-AES128-GCM-SHA256
[+] 2.2.2.2:443    - Connected with SSL Version: TLSv1.2, Cipher: DHE-RSA-AES128-GCM-SHA256
[*] 2.2.2.2:443    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
