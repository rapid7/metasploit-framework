The `smb_lookupsid` module bruteforces the SID of the user, to obtain the username or group name.
This module works against Windows and Samba.
This module can also be used to lookup the information against a Domain utilizing the `action` option.
SID 500 is always the default administrator account, while user accounts start in the 1000 range.

## Vulnerable Application

To use `smb_lookupsid`, make sure you are able to connect to a SMB service that supports SMBv1.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/smb_lookupsid``` 
2. Do: ```set rhosts [IP]```
3. Do: ```run```

## Scenarios

### Windows 2000 SP4

```
msf > use auxiliary/scanner/smb/smb_lookupsid 
msf auxiliary(smb_lookupsid) > set rhosts 10.9.7.127
rhosts => 10.9.7.127

[*] 10.9.7.127:445     - PIPE(LSARPC) LOCAL(WIN2K - 5-21-484763869-823518204-682003330) DOMAIN(RAGEGROUP - )
[*] 10.9.7.127:445     - USER=renamedAdministrator RID=500
[*] 10.9.7.127:445     - USER=Guest RID=501
[*] 10.9.7.127:445     - GROUP=None RID=513
[*] 10.9.7.127:445     - USER=disabled RID=1000
[*] 10.9.7.127:445     - USER=test RID=1001
[*] 10.9.7.127:445     - WIN2K [renamedAdministrator, Guest, disabled, test ]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Metasploitable2 (Samba)

```
msf auxiliary(smb_lookupsid) > run

[*] Scanned  26 of 253 hosts (10% complete)
[*] 10.9.7.35:139      - PIPE(LSARPC) LOCAL(METASPLOITABLE - 5-21-1042354039-2475377354-766472396) DOMAIN(WORKGROUP - )
[*] 10.9.7.35:139      - USER=Administrator RID=500
[*] 10.9.7.35:139      - USER=nobody RID=501
[*] 10.9.7.35:139      - GROUP=Domain Admins RID=512
[*] 10.9.7.35:139      - GROUP=Domain Users RID=513
[*] 10.9.7.35:139      - GROUP=Domain Guests RID=514
[*] 10.9.7.35:139      - USER=root RID=1000
[*] 10.9.7.35:139      - GROUP=root RID=1001
[*] 10.9.7.35:139      - USER=daemon RID=1002
[*] 10.9.7.35:139      - GROUP=daemon RID=1003
[*] 10.9.7.35:139      - USER=bin RID=1004
[*] 10.9.7.35:139      - GROUP=bin RID=1005
[*] 10.9.7.35:139      - USER=sys RID=1006
[*] 10.9.7.35:139      - GROUP=sys RID=1007
```
...snip...

```
[*] 10.9.7.35:139      - USER=user RID=3002
[*] 10.9.7.35:139      - GROUP=user RID=3003
[*] 10.9.7.35:139      - USER=service RID=3004
[*] 10.9.7.35:139      - GROUP=service RID=3005
[*] 10.9.7.35:139      - METASPLOITABLE [Administrator, nobody, root, daemon, bin, sys, sync, games, man, lp, mail, news, uucp, proxy, www-data, backup, list, irc, gnats, libuuid, dhcp, syslog, klog, sshd, bind, postfix, ftp, postgres, mysql, tomcat55, distccd, telnetd, proftpd, statd, msfadmin, user, service ]
```

## Confirmation with nmap

NMAP utilizes [smb-enum-users](https://nmap.org/nsedoc/scripts/smb-enum-users.html) to do SID bruteforcing.

```
nmap --script smb-enum-users.nse -p445 10.9.7.127,35

Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-19 14:36 EDT
Nmap scan report for 10.9.7.35
Host is up (0.0013s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:59:D4:F7 (VMware)

Host script results:
| smb-enum-users: 
|   METASPLOITABLE\backup (RID: 1068)
|     Full name:   backup
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\bin (RID: 1004)
|     Full name:   bin
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\bind (RID: 1210)
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\daemon (RID: 1002)
|     Full name:   daemon
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\dhcp (RID: 1202)
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\distccd (RID: 1222)
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\ftp (RID: 1214)
|     Flags:       Account disabled, Normal user account
```
...snip...

```
|   METASPLOITABLE\tomcat55 (RID: 1220)
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\user (RID: 3002)
|     Full name:   just a user,111,,
|     Flags:       Normal user account
|   METASPLOITABLE\uucp (RID: 1020)
|     Full name:   uucp
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\www-data (RID: 1066)
|     Full name:   www-data
|_    Flags:       Account disabled, Normal user account

Nmap scan report for win2k (10.9.7.127)
Host is up (0.0013s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:C8:97:2D (VMware)

Host script results:
| smb-enum-users: 
|   WIN2K\disabled (RID: 1000)
|     Full name:   disabled
|     Description: user account is disabled
|     Flags:       Account disabled, Normal user account
|   WIN2K\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Password not required, Password does not expire, Account disabled, Normal user account
|   WIN2K\renamedAdministrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Password does not expire, Normal user account
|   WIN2K\test (RID: 1001)
|     Full name:   test
|_    Flags:       Normal user account

Nmap done: 2 IP addresses (2 hosts up) scanned in 0.62 seconds
```