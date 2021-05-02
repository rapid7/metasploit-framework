## Verification Steps

1. Install [Impacket][1] v0.9.17 from GitHub. The `impacket` package must be in
   Python's module path, so `import impacket` works from any directory.
1. Install [pycrypto][2] v2.7 (the experimental release). Impacket requires this
   specific version.
1. Start msfconsole
1. Do: `use auxiliary/scanner/smb/impacket/wmiexec`
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
metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/wmiexec) > show options 

Module options (auxiliary/scanner/smb/impacket/wmiexec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMAND    ipconfig         yes       The command to execute
   OUTPUT     true             yes       Get the output of the executed command
   RHOSTS     192.168.90.11    yes       The target address range or CIDR identifier
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    wakawaka         yes       The password for the specified username
   SMBUser    spencer          yes       The username to authenticate as
   THREADS    1                yes       The number of concurrent threads

metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/wmiexec) > run

[*] [2018.04.04-17:10:47] Running for 192.168.90.11...
[*] [2018.04.04-17:10:47] 192.168.90.11 - SMBv3.0 dialect used
[*] [2018.04.04-17:10:47] 192.168.90.11 - Target system is 192.168.90.11 and isFDQN is False
[*] [2018.04.04-17:10:47] 192.168.90.11 - StringBinding: \\\\WINDOWS8VM[\\PIPE\\atsvc]
[*] [2018.04.04-17:10:47] 192.168.90.11 - StringBinding: Windows8VM[49154]
[*] [2018.04.04-17:10:47] 192.168.90.11 - StringBinding: 10.0.3.15[49154]
[*] [2018.04.04-17:10:47] 192.168.90.11 - StringBinding: 192.168.90.11[49154]
[*] [2018.04.04-17:10:47] 192.168.90.11 - StringBinding chosen: ncacn_ip_tcp:192.168.90.11[49154]
[*] [2018.04.04-17:10:49] 
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

[*] [2018.04.04-17:10:49] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

[1]: https://github.com/CoreSecurity/impacket
[2]: https://www.dlitz.net/software/pycrypto/
