The `smb_version` module is used to determine what version of the Operating System is installed.
This module also attempts to determine the following information on the system if possible:

1. OS (product and version)
2. lanman version
3. OS build number
4. Service pack
5. OS language

## Vulnerable Application

To use `smb_version`, make sure you are able to connect to a SMB service that supports SMBv1.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/smb_version``` 
2. Do: ```set rhosts [IP]```
3. Do: ```run```

## Scenarios

This is an example run of a network with several different version of Windows, metasploit 1 and 2, and a NAS device running SAMBA.

```
msf > use auxiliary/scanner/smb/smb_version 
msf auxiliary(smb_version) > set rhosts 10.9.7.1-254
rhosts => 10.9.7.1-254
msf auxiliary(smb_version) > set threads 5
threads => 5
msf auxiliary(smb_version) > run

[*] 10.9.7.7:445       - Host is running Windows 2008 R2 Standard (build:7600) (name:WIN-O712LQK2K69) (workgroup:WORKGROUP )
[*] Scanned  26 of 254 hosts (10% complete)
[*] 10.9.7.35:445      - Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] 10.9.7.46:445      - Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] Scanned  52 of 254 hosts (20% complete)
[*] Scanned  77 of 254 hosts (30% complete)
[*] 10.9.7.91:445      - Host is running Windows 8.1 Enterprise Evaluation (build:9600) (name:IE11WIN8_1) (workgroup:WORKGROUP )
[*] Scanned 105 of 254 hosts (41% complete)
[*] 10.9.7.108:445     - Host is running Windows XP SP3 (language:English) (name:WINXP) (workgroup:WORKGROUP )
[*] 10.9.7.119:445     - Host could not be identified: Windows 6.1 (Samba 4.4.9)
[*] 10.9.7.127:445     - Host is running Windows 2000 SP4 with ms05-010+ (language:English) (name:WIN2K) (workgroup:WORKGROUP )
[*] Scanned 127 of 254 hosts (50% complete)
[*] Scanned 154 of 254 hosts (60% complete)
[*] 10.9.7.164:445     - Host is running Windows 2012 Standard (build:9200) (name:WIN-OBKF2JFCDKL)
[*] 10.9.7.175:445     - Host is running Windows 10 Pro (build:14393) (name:WORKDESK)
[*] Scanned 178 of 254 hosts (70% complete)
[*] Scanned 204 of 254 hosts (80% complete)
[*] Scanned 231 of 254 hosts (90% complete)
[*] 10.9.7.232:445     - Host is running Windows 7 Enterprise SP1 (build:7601) (name:IE11WIN7) (workgroup:WORKGROUP )
[*] Scanned 254 of 254 hosts (100% complete)
[*] Auxiliary module execution completed
```