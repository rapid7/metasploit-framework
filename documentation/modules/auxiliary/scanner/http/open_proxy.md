## Description

Checks if an HTTP proxy is open. False positives are avoided by verifying the HTTP return code and matching a pattern. The CONNECT method is verified only by the return code. HTTP headers are shown regarding the use of proxies or load balancers.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/open_proxy```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

### Running the scanner :

```
msf > use auxiliary/scanner/http/open_proxy 
msf auxiliary(open_proxy) > show options

Module options (auxiliary/scanner/http/open_proxy):

   Name           Current Setting           Required  Description
   ----           ---------------           --------  -----------
   CHECKURL       http://www.google.com     yes       The web site to test via alleged web proxy
   MULTIPORTS     false                     no        Multiple ports will be used: 80, 443, 1080, 3128, 8000, 8080, 8123
   Proxies                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                   yes       The target address range or CIDR identifier
   RPORT          8080                      yes       The target port (TCP)
   SSL            false                     no        Negotiate SSL/TLS for outgoing connections
   THREADS        1                         yes       The number of concurrent threads
   VALIDCODES     200,302                   yes       Valid HTTP code for a successfully request
   VALIDPATTERN   <TITLE>302 Moved</TITLE>  yes       Valid pattern match (case-sensitive into the headers and HTML body) for a successfully request
   VERIFYCONNECT  false                     no        Enable CONNECT HTTP method check
   VHOST                                    no        HTTP server virtual host

msf auxiliary(open_proxy) > set RHOSTS 192.168.1.200-210
RHOSTS => 192.168.1.200-210
msf auxiliary(open_proxy) > set RPORT 8888
RPORT => 8888
msf auxiliary(open_proxy) > set THREADS 11
THREADS => 11
msf auxiliary(open_proxy) > run

[*] 192.168.1.201:8888 is a potentially OPEN proxy [200] (n/a)
[*] Scanned 02 of 11 hosts (018% complete)
[*] Scanned 03 of 11 hosts (027% complete)
[*] Scanned 04 of 11 hosts (036% complete)
[*] Scanned 05 of 11 hosts (045% complete)
[*] Scanned 11 of 11 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(open_proxy) >
```
