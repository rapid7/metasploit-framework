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
msf auxiliary(smb_lookupsid) > set rhosts 192.168.2.127
rhosts => 192.168.2.127

[*] 192.168.2.127:445     - PIPE(LSARPC) LOCAL(WIN2K - 5-21-484763869-823518204-682003330) DOMAIN(RAGEGROUP - )
[*] 192.168.2.127:445     - USER=renamedAdministrator RID=500
[*] 192.168.2.127:445     - USER=Guest RID=501
[*] 192.168.2.127:445     - GROUP=None RID=513
[*] 192.168.2.127:445     - USER=disabled RID=1000
[*] 192.168.2.127:445     - USER=test RID=1001
[*] 192.168.2.127:445     - WIN2K [renamedAdministrator, Guest, disabled, test ]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Metasploitable2 (Samba)

```
msf auxiliary(smb_lookupsid) > run

[*] Scanned  26 of 253 hosts (10% complete)
[*] 192.168.2.35:139      - PIPE(LSARPC) LOCAL(METASPLOITABLE - 5-21-1042354039-2475377354-766472396) DOMAIN(WORKGROUP - )
[*] 192.168.2.35:139      - USER=Administrator RID=500
[*] 192.168.2.35:139      - USER=nobody RID=501
[*] 192.168.2.35:139      - GROUP=Domain Admins RID=512
[*] 192.168.2.35:139      - GROUP=Domain Users RID=513
[*] 192.168.2.35:139      - GROUP=Domain Guests RID=514
[*] 192.168.2.35:139      - USER=root RID=1000
[*] 192.168.2.35:139      - GROUP=root RID=1001
[*] 192.168.2.35:139      - USER=daemon RID=1002
[*] 192.168.2.35:139      - GROUP=daemon RID=1003
[*] 192.168.2.35:139      - USER=bin RID=1004
[*] 192.168.2.35:139      - GROUP=bin RID=1005
[*] 192.168.2.35:139      - USER=sys RID=1006
[*] 192.168.2.35:139      - GROUP=sys RID=1007
```
...snip...

```
[*] 192.168.2.35:139      - USER=user RID=3002
[*] 192.168.2.35:139      - GROUP=user RID=3003
[*] 192.168.2.35:139      - USER=service RID=3004
[*] 192.168.2.35:139      - GROUP=service RID=3005
[*] 192.168.2.35:139      - METASPLOITABLE [Administrator, nobody, root, daemon, bin, sys, sync, games, man, lp, mail, news, uucp, proxy, www-data, backup, list, irc, gnats, libuuid, dhcp, syslog, klog, sshd, bind, postfix, ftp, postgres, mysql, tomcat55, distccd, telnetd, proftpd, statd, msfadmin, user, service ]
```