## Description

This module shows HTTP Headers returned by the scanned systems.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/http_header```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

**Running the scanner**

```
msf > use auxiliary/scanner/http/http_header 
msf auxiliary(http_header) > show options

Module options (auxiliary/scanner/http/http_header):

   Name         Current Setting                                                        Required  Description
   ----         ---------------                                                        --------  -----------
   HTTP_METHOD  HEAD                                                                   yes       HTTP Method to use, HEAD or GET (Accepted: GET, HEAD)
   IGN_HEADER   Vary,Date,Content-Length,Connection,Etag,Expires,Pragma,Accept-Ranges  yes       List of headers to ignore, seperated by comma
   Proxies                                                                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                              yes       The target address range or CIDR identifier
   RPORT        80                                                                     yes       The target port (TCP)
   SSL          false                                                                  no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                                                                      yes       The URI to use
   THREADS      1                                                                      yes       The number of concurrent threads
   VHOST                                                                               no        HTTP server virtual host

msf auxiliary(http_header) > set RHOSTS 192.168.56.101
RHOSTS => 192.168.56.101
msf auxiliary(http_header) > run

[+] 192.168.56.101:80    : CONTENT-TYPE: text/html
[+] 192.168.56.101:80    : SERVER: Apache/2.2.8 (Ubuntu) DAV/2
[+] 192.168.56.101:80    : X-POWERED-BY: PHP/5.2.4-2ubuntu5.10
[+] 192.168.56.101:80    : detected 3 headers
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(http_header) > 

```
