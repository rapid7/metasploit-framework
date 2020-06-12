The `smb_version` module is used to determine information about a remote SMB server. It will fingerprint protocol
version and capability information. If the target server supports SMB version 1, then the module will also attempt to
identify the information about the host operating system.

### Protocol Information

1. Protocol Versions: The list of SMB protocol versions that the server supports.
1. Preferred Dialect: The preferred dialect for the newest protocol version that the server supports.
1. Signature Requirements: Whether or not the server requires security signatures.
1. Uptime: How long the server has been up, as calculated by subtracting the current time from the system time. This 
   calculation requires that both fields be provided by the server. If one or both fields are unset, this value will be
   omitted.
    * Requires versions: 2+
1. Server GUID: The unique identifier of the server. This value can be used to identify systems with multiple network 
   interfaces.
    * Requires versions: 2+
1. Capabilities: The supported encryption and compression algorithms that the server supports.
    * Requires versions: 3+

### Host Operating System Information

*This information is only available if the target SMB server supports SMB version 1.*

1. OS (product and version)
1. LAN Manager version
1. OS build number
1. Service pack
1. OS language

## Verification Steps

1. Do: `use auxiliary/scanner/smb/smb_version`
2. Do: `set rhosts [IP]`
3. Do: `run`

## Scenarios

This is an example run of a network with several different version of Windows, metasploit 1 and 2, and a NAS device running SAMBA.

```
msf5 auxiliary(scanner/smb/smb_version) > show options 

Module options (auxiliary/scanner/smb/smb_version):

   Name       Current Setting           Required  Description
   ----       ---------------           --------  -----------
   RHOSTS     file:smb_servers.txt      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   SMBDomain  .                         no        The Windows domain to use for authentication
   SMBPass                              no        The password for the specified username
   SMBUser                              no        The username to authenticate as
   THREADS    5                         yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.0.94:445      - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1) (encryption capabilities:AES-128-CCM) (signatures:optional) (guid:{a13d40f9-c789-44f6-b5b0-14d4bd633284})
[*] 192.168.0.212:445     - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.0.2) (signatures:optional) (uptime:7w 6d 11h 52m) (guid:{9874f7e3-5178-4db9-af57-113adf0b67b9})
[+] 192.168.0.212:445     -   Host is running Windows 2012 R2 Standard (build:9600) (name:WIN-R1FK95KGVJ5)
[*] 192.168.0.107:445     - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1) (encryption capabilities:AES-128-CCM) (signatures:optional) (uptime:7w 6d 11h 52m) (guid:{515c49bb-24c3-4092-825a-62afd6e1bd45})
[+] 192.168.0.107:445     -   Host is running Windows 2016 Datacenter (build:14393) (name:EC2AMAZ-IO7R6NR)
[*] Scanned 2 of 4 hosts (50% complete)
[*] Scanned 3 of 4 hosts (75% complete)
[*] 192.168.0.100:445     - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:7w 6d 12h 31m) (guid:{c21f4e2f-1e0a-4dd1-96a4-5dad6465a2ab})
[+] 192.168.0.100:445     -   Host is running Windows 2008 R2 Datacenter SP1 (build:7601) (name:WIN-RHDA4UK6PF6) (workgroup:WORKGROUP)
[*] Scanned 4 of 4 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_version) > 
```
