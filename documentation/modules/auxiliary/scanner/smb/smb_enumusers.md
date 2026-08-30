The `smb_enumusers` module enumerates users via SAM User Enumeration over the SMB user interface.
This module works against Windows and Samba.

## Vulnerable Application

To use `smb_enumusers`, make sure you are able to connect to a SMB service that supports SMBv1.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/smb_enumusers``` 
2. Do: ```set rhosts [IP]```
3. Do: ```run```

## Scenarios

### Metasploitable2 (Samba)

```
msf auxiliary(smb_enumusers) > run

[+] 10.9.7.35:139      - METASPLOITABLE [ games, nobody, bind, proxy, syslog, user, www-data, root, news, postgres, bin, mail, distccd, proftpd, dhcp, daemon, sshd, man, lp, mysql, gnats, libuuid, backup, msfadmin, telnetd, sys, klog, postfix, service, list, irc, ftp, tomcat55, sync, uucp ] ( LockoutTries=0 PasswordMin=5 )
```

### Windows 2000 SP4

```
[+] 10.9.7.127:445     - WIN2K [ disabled, Guest, renamedAdministrator, test ] ( LockoutTries=0 PasswordMin=0 )
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