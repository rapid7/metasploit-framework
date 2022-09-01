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
1. Authentication Domain: The domain that the server prompts the user to authenticate to when attempting to login.

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
msf5 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.159.0/24
RHOSTS => 192.168.159.0/24
msf5 auxiliary(scanner/smb/smb_version) > show options 

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting   Required  Description
   ----     ---------------   --------  -----------
   RHOSTS   192.168.159.0/24  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   THREADS  15                yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.159.10:445    - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1) (encryption capabilities:AES-128-CCM) (signatures:required) (guid:{faf5534c-d125-4081-aa2a-cf3256415908}) (authentication domain:MSFLAB)
[*] 192.168.159.10:445    -   Host could not be identified: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
[*] 192.168.159.30:445    - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1) (encryption capabilities:AES-128-CCM) (signatures:optional) (guid:{8f1ce8b7-e198-404e-89d6-a27297b1c3f2}) (authentication domain:DESKTOP-RTCRBEV)
[*] 192.168.159.0/24:     - Scanned  30 of 256 hosts (11% complete)
[*] 192.168.159.38:445    - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.0.2) (signatures:optional) (uptime:4d 17h 33m 34s) (guid:{cd5d41db-0bb8-4954-9421-0cdd14b7c6f7}) (authentication domain:WIN-46IL3RC2FHI)
[*] 192.168.159.31:445    - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:3m 6s) (guid:{caaee1a3-8f74-4dd0-b0eb-436d7abc8979}) (authentication domain:WIN-9NSI4A6AIHJ)
[+] 192.168.159.31:445    -   Host is running Windows 7 Professional SP1 (build:7601) (name:WIN-9NSI4A6AIHJ) (workgroup:WORKGROUP)
[*] 192.168.159.48:445    - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[+] 192.168.159.48:445    -   Host is running Windows XP SP2 (language:English) (name:SMCINTYR-81CC7C) (workgroup:WORKGROUP)
[*] 192.168.159.0/24:     - Scanned  57 of 256 hosts (22% complete)
[*] 192.168.159.0/24:     - Scanned  87 of 256 hosts (33% complete)
[*] 192.168.159.0/24:     - Scanned 104 of 256 hosts (40% complete)
[*] 192.168.159.128:445   - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZ77) (encryption capabilities:AES-128-GCM) (signatures:optional) (guid:{61636f6c-686c-736f-7400-000000000000}) (authentication domain:LOCALHOST)
[*] 192.168.159.129:445   - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1) (encryption capabilities:AES-128-CCM) (signatures:optional) (guid:{19147a6c-08c1-4e9c-b6c5-1119e2c57e6a}) (authentication domain:DESKTOP-R9TM84E)
[+] 192.168.159.129:445   -   Host is running Windows 10 Enterprise (build:17763) (name:DESKTOP-R9TM84E) (workgroup:WORKGROUP)
[*] 192.168.159.0/24:     - Scanned 137 of 256 hosts (53% complete)
[*] 192.168.159.0/24:     - Scanned 163 of 256 hosts (63% complete)
[*] 192.168.159.0/24:     - Scanned 180 of 256 hosts (70% complete)
[*] 192.168.159.0/24:     - Scanned 205 of 256 hosts (80% complete)
[*] 192.168.159.0/24:     - Scanned 234 of 256 hosts (91% complete)
[*] 192.168.159.0/24:     - Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_version) > 
```
