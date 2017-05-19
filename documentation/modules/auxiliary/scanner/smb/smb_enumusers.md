The `smb_enumusers` module ?????????????????????????????????
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

[+] 192.168.2.35:139      - METASPLOITABLE [ games, nobody, bind, proxy, syslog, user, www-data, root, news, postgres, bin, mail, distccd, proftpd, dhcp, daemon, sshd, man, lp, mysql, gnats, libuuid, backup, msfadmin, telnetd, sys, klog, postfix, service, list, irc, ftp, tomcat55, sync, uucp ] ( LockoutTries=0 PasswordMin=5 )
```

### Windows 2000 SP4

```
[+] 192.168.2.127:445     - WIN2K [ disabled, Guest, renamedAdministrator, test ] ( LockoutTries=0 PasswordMin=0 )
```