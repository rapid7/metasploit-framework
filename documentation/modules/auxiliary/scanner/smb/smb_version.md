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

## Confirmation with nmap

There are several scripts that attempt to validate OS information through SMB.  The most equivalent is [smb-os-discovery](https://nmap.org/nsedoc/scripts/smb-os-discovery.html).

```
nmap --script smb-os-discovery.nse -p445 10.9.7.7,35,91,108,119,127,164,175,232

Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-19 14:12 EDT
Nmap scan report for WIN-O712LQK2K69 (10.9.7.7)
Host is up (0.0025s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:28:DD:A0 (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7600 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::-
|   Computer name: WIN-O712LQK2K69
|   NetBIOS computer name: WIN-O712LQK2K69\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-05-19T11:12:15-07:00

Nmap scan report for 10.9.7.35
Host is up (0.0018s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:59:D4:F7 (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-05-19T14:33:31-04:00

Nmap scan report for IE11Win8_1 (10.9.7.91)
Host is up (0.0020s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:E0:CF:FB (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Windows 8.1 Enterprise Evaluation 9600 (Windows 8.1 Enterprise Evaluation 6.3)
|   OS CPE: cpe:/o:microsoft:windows_8.1::-
|   NetBIOS computer name: IE11WIN8_1\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-05-19T11:04:48-07:00

Nmap scan report for winxp (10.9.7.108)
Host is up (0.0018s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:D6:24:67 (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: winxp
|   NetBIOS computer name: WINXP\x00
|   Workgroup: RAGEGROUP\x00
|_  System time: 2017-05-19T14:12:29-04:00

Nmap scan report for workNAS (10.9.7.119)
Host is up (0.0024s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:11:32:10:FE:C4 (Synology Incorporated)

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.4.9)
|   Computer name: worknas
|   NetBIOS computer name: WORKNAS\x00
|   Domain name: \x00
|   FQDN: worknas
|_  System time: 2017-05-19T14:12:41-04:00

Nmap scan report for win2k (10.9.7.127)
Host is up (0.0025s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:C8:97:2D (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Windows 2000 (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_2000::-
|   Computer name: win2k
|   NetBIOS computer name: WIN2K\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-05-19T14:04:37-04:00

Nmap scan report for IE11Win7 (10.9.7.232)
Host is up (0.0019s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:7D:29:4C (VMware)

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Enterprise 7601 Service Pack 1 (Windows 7 Enterprise 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: IE11Win7
|   NetBIOS computer name: IE11WIN7\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-05-19T11:04:46-07:00

Nmap done: 8 IP addresses (7 hosts up) scanned in 4.67 seconds

```