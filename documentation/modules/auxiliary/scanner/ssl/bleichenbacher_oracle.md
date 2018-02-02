Some TLS implementations handle errors processing RSA key exchanges and encryption (PKCS #1 v1.5 messages) in a broken way that leads an adaptive chosen-chiphertext attack. Attackers cannot recover a server's private key, but they can decrypt and sign messages with it. A strong oracle occurs when the TLS server does not strictly check message formatting and needs less than a million requests on average to decode a given ciphertext. A weak oracle server strictly checks message formatting and often requires many more requests to perform the attack.

## Vulnerable Applications

* F5 BIG-IP 11.6.0-11.6.2 (fixed in 11.6.2 HF1), 12.0.0-12.1.2 HF1 (fixed in 12.1.2 HF2), or 13.0.0-13.0.0 HF2 (fixed in 13.0.0 HF3) (CVE 2017-6168)
* Citrix NetScaler Gateway 10.5 before build 67.13, 11.0 before build 71.22, 11.1 before build 56.19, and 12.0 before build 53.22 (CVE 2017-17382)
* Radware Alteon firmware 31.0.0.0-31.0.3.0 (CVE 2017-17427)
* Cisco ACE (CVE 2017-17428)
* Cisco ASA 5500 series (CVE 2017-12373)
* Bouncy Castle TLS < 1.0.3 configured to use the Java Cryptography Engine (CVE 2017-13098)
* Erlang  < 20.1.7, < 19.3.6.4, < 18.3.4.7 (CVE 2017-1000385)
* WolfSSL < 3.12.2 (CVE 2017-13099)
* MatrixSSL 3.8.3 (CVE 2016-6883)
* Oracle Java <= 7u7, <= 6u35, <= 5u36, <= 1.4.2_38  (CVE 2012-5081)
* IBM Domino
* Palo Alto PAN-OS

(source: [https://robotattack.org/#patches](https://robotattack.org/#patches))

## Extra requirements

This module requires a working Python 3 install with the `cryptography` and `gmpy2` packages installed (e.g. via `pip3 install cryptography gmpy2`).

## Verification Steps

Perhaps the easiest way to reproduce is to install an older version of Erlang on Linux (the stock `erlang` package on Ubuntu 17.10 and before is unpatched), and run the [ssl_hello_world](https://github.com/ninenines/cowboy/tree/master/examples/ssl_hello_world) example from Cowboy (additionally requires `git` and `make`, be sure to use the 1.1.x branch for Erlang < 19).

```
msf4 > use auxiliary/scanner/ssl/robot 
msf4 auxiliary(scanner/ssl/robot) > set RHOSTS 192.168.244.128
RHOSTS => 192.168.244.128
msf4 auxiliary(scanner/ssl/robot) > set RPORT 8443
RPORT => 8443
msf4 auxiliary(scanner/ssl/robot) > set VERBOSE true
VERBOSE => true
msf4 auxiliary(scanner/ssl/robot) > run

[*] Running for 192.168.244.128...
[*] 192.168.244.128:8443 - Scanning host for Bleichenbacher oracle
[*] 192.168.244.128:8443 - RSA N: 0xcdb5b51a3102cc751cfd6493a8b8801aa8c235c711e6c6954beca8cf648f461a68c9fd3fa81ad7e41634b739a0a33a138917c4e300a2543f7d09cf83ae9fc5338f6be04a59768708a2fa6b98e9affe0c24a23f79cda03a3ca367d4e7660e9da1c09b17d999b79296c65194f18c392471c9a051be048cbeea347abbb1a42d8af5
[*] 192.168.244.128:8443 - RSA e: 0x10001
[*] 192.168.244.128:8443 - Modulus size: 1024 bits, 128 bytes
[+] 192.168.244.128:8443 - Vulnerable: (strong) oracle found TLSv1.2 with standard message flow
[*] 192.168.244.128:8443 - Result of good request:                        TLS alert 10 of length 7
[*] 192.168.244.128:8443 - Result of bad request 1 (wrong first bytes):   TLS alert 51 of length 7
[*] 192.168.244.128:8443 - Result of bad request 2 (wrong 0x00 position): TLS alert 10 of length 7
[*] 192.168.244.128:8443 - Result of bad request 3 (missing 0x00):        TLS alert 51 of length 7
[*] 192.168.244.128:8443 - Result of bad request 4 (bad TLS version):     TLS alert 10 of length 7
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf4 auxiliary(scanner/ssl/robot) > 
```

## Options

The scanner takes the normal `RHOSTS` and `RPORT` options to specify the hosts to scan on the port on which to scan them. In addition, it takes two options for the TLS behaviour: `cipher_group` and `timeout`.

The `cipher_group` option:

Select the ciphers to use to negotiate: all TLS_RSA ciphers (`all`, the default), TLS_RSA_WITH_AES_128_CBC_SHA (`cbc`), or TLS-RSA-WITH-AES-128-GCM-SHA256 (`gcm`).

```
set cipher_group gcm
```

The `timeout` option:

Set the interval to wait before considering the TLS connection timed out. The default is 5 seconds.

```
set timeout 10
```
