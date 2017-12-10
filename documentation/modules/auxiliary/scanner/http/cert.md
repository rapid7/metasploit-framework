## Description

This module is a useful administrative scanner that allows you to cover a subnet to check whether or not server certificates are expired. Using this scanner, you can uncover issuer of certificate, issue and expiry date. If you find a expired certificate, you can exploit it.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/cert```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

Just set target RHOSTS and THREADS values and let it do its thing.

## Scenarios

**Running the scanner**

```
msf > use auxiliary/scanner/http/cert
msf auxiliary(cert) > show options

Module options:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ISSUER   .*               yes       Show a warning if the Issuer doesn't match this regex
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    443              yes       The target port
   SHOWALL  false            no        Show all certificates (issuer,time) regardless of match
   THREADS  1                yes       The number of concurrent threads

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