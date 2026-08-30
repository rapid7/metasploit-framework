## Description

This module identifies the existence of interesting files in a given directory path.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/files_dir```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

**Running the scanner**

```
msf > use auxiliary/scanner/http/files_dir 
msf auxiliary(files_dir) > show options

Module options (auxiliary/scanner/http/files_dir):

   Name        Current Setting                                                    Required  Description
   ----        ---------------                                                    --------  -----------
   DICTIONARY  /root/Framework/msf/metasploit-framework/data/wmap/wmap_files.txt  no        Path of word dictionary to use
   EXT                                                                            no        Append file extension to use
   PATH        /                                                                  yes       The path  to identify files
   Proxies                                                                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                         yes       The target address range or CIDR identifier
   RPORT       80                                                                 yes       The target port (TCP)
   SSL         false                                                              no        Negotiate SSL/TLS for outgoing connections
   THREADS     1                                                                  yes       The number of concurrent threads
   VHOST                                                                          no        HTTP server virtual host

msf auxiliary(files_dir) > set RHOSTS 192.168.0.155
RHOSTS => 192.168.0.155
msf auxiliary(files_dir) > run

[*] Using code '404' as not found for files with extension .null
[*] Using code '404' as not found for files with extension .backup
[*] Using code '404' as not found for files with extension .bak
[*] Using code '404' as not found for files with extension .c
[*] Using code '404' as not found for files with extension .cfg
[*] Using code '404' as not found for files with extension .class
[*] Using code '404' as not found for files with extension .copy
[*] Using code '404' as not found for files with extension .conf
[*] Using code '404' as not found for files with extension .exe
[*] Using code '404' as not found for files with extension .html
[*] Found http://192.168.0.155:80/index.html 200
[*] Using code '404' as not found for files with extension .htm
[*] Using code '404' as not found for files with extension .ini
[*] Using code '404' as not found for files with extension .log
[*] Using code '404' as not found for files with extension .old
[*] Using code '404' as not found for files with extension .orig
[*] Using code '404' as not found for files with extension .php
[*] Using code '404' as not found for files with extension .tar
[*] Using code '404' as not found for files with extension .tar.gz
[*] Using code '404' as not found for files with extension .tgz
[*] Using code '404' as not found for files with extension .tmp
[*] Using code '404' as not found for files with extension .temp
[*] Using code '404' as not found for files with extension .txt
[*] Using code '404' as not found for files with extension .zip
[*] Using code '404' as not found for files with extension ~
[*] Using code '404' as not found for files with extension
[*] Found http://192.168.0.155:80/blog 301
[*] Found http://192.168.0.155:80/index 200
[*] Using code '404' as not found for files with extension
[*] Found http://192.168.0.155:80/blog 301
[*] Found http://192.168.0.155:80/index 200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(files_dir) >
```
