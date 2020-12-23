## Description
This module will scan a range of machines and prints the banner, usually containing the version of any telnet servers that are running on it.

## Verification Steps

1. Do: ```use auxiliary/scanner/telnet/telnet_version```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/telnet/telnet_version 
msf auxiliary(scanner/telnet/telnet_version) > set RHOSTS 1.1.1.0/24
RHOSTS => 1.1.1.0/24
msf auxiliary(scanner/telnet/telnet_version) > set THREADS 254
THREADS => 254
msf auxiliary(scanner/telnet/telnet_version) > run

[*] 1.1.1.2:23 TELNET (GSM7224) \x0aUser:
[*] 1.1.1.56:23 TELNET Ubuntu 8.04\x0ametasploitable login:
[*] 1.1.1.116:23 TELNET Welcome to GoodTech Systems Telnet Server for Windows NT/2000/XP (Evaluation Copy)\x0a\x0a(C) Copyright 1996-2002 GoodTech Systems, Inc.\x0a\x0a\x0aLogin username:
[*] Scanned 254 of 256 hosts (099% complete)
[*] Scanned 255 of 256 hosts (099% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/telnet/telnet_version) >
```


