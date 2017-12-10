## Description

This module scans one or more web servers for interesting directories that can be further explored.

## Verfication Steps

1. Do: ```use auxiliary/scanner/http/dir_scanner```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

Let the default dictionary included in Metasploit set, set our target, and let the scanner run.

## Scenarios

**Running the scanner**

```
> use auxiliary/scanner/http/dir_scanner
msf auxiliary(dir_scanner) > show options

Module options (auxiliary/scanner/http/dir_scanner):

   Name        Current Setting                                          Required  Description
   ----        ---------------                                          --------  -----------
   DICTIONARY  /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt  no        Path of word dictionary to use
   PATH        /                                                        yes       The path  to identify files
   Proxies                                                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                               yes       The target address range or CIDR identifier
   RPORT       80                                                       yes       The target port (TCP)
   SSL         false                                                    no        Negotiate SSL/TLS for outgoing connections
   THREADS     1                                                        yes       The number of concurrent threads
   VHOST                                                                no        HTTP server virtual host

msf auxiliary(dir_scanner) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(dir_scanner) > run

[*] Using code '404' as not found for 192.168.1.201
[*] Found http://192.168.1.201:80/.../ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/Joomla/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/cgi-bin/ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/error/ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/icons/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/oscommerce/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/phpmyadmin/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/security/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/webalizer/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/webdav/ 200 (192.168.1.201)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_scanner) >
```

A quick scan has turned up a number of directories on the target server that could be certainly investigated further.
