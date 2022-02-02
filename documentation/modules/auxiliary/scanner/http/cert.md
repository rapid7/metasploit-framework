## Description

This module is a useful administrative scanner that allows you to cover a subnet to check whether or not server http certificates are expired. Using this scanner, you can uncover issuer of certificate, issue and expiry date.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/cert```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/http/cert
msf auxiliary(cert) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf auxiliary(cert) > set THREADS 254
THREADS => 254
msf auxiliary(cert) > run

[*] 192.168.1.11 - '192.168.1.11' : 'Sat Sep 25 07:16:02 UTC 2010' - 'Tue Sep 22 07:16:02 UTC 2020'
[*] 192.168.1.10 - '192.168.1.10' : 'Wed Mar 10 00:13:26 UTC 2010' - 'Sat Mar 07 00:13:26 UTC 2020'
[*] 192.168.1.201 - 'localhost' : 'Tue Nov 10 23:48:47 UTC 2009' - 'Fri Nov 08 23:48:47 UTC 2019'
[*] Scanned 255 of 256 hosts (099% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(cert) >
```

## Confirming

The following are other industry tools which can also be used.  Note that the targets are not the same as those used in the previous documentation.

### [nmap](https://nmap.org/nsedoc/scripts/ssl-cert.html)

```
# nmap -p 443 192.168.2.137 -sV --script=ssl-cert

Starting Nmap 7.60 ( https://nmap.org ) at 2018-02-24 13:20 EST
Nmap scan report for ubuntu (192.168.2.137)
Host is up (0.0029s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-01-26T21:38:21
| Not valid after:  2028-01-24T21:38:21
| MD5:   d2a7 364d 636a 6eee c3e1 7af9 05f7 8c5b
|_SHA-1: a5bf f783 2514 90ee 365a 3ee4 9b6c 23f6 24af dbfa
MAC Address: 00:0C:29:5B:CF:75 (VMware)
```

### [sslscan](https://github.com/rbsec/sslscan)
```
# sslscan 192.168.2.137
Version: 1.11.11-static
OpenSSL 1.0.2-chacha (1.0.2g-dev)

Connected to 192.168.2.137

Testing SSL server 192.168.2.137 on port 443 using SNI name 192.168.2.137
```
...snip...
```
Subject:  ubuntu
Issuer:   ubuntu

Not valid before: Jan 26 21:38:21 2018 GMT
Not valid after:  Jan 24 21:38:21 2028 GMT
```
