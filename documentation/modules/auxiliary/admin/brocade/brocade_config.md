## General Notes

This module imports a Brocade configuration file into the database.
This is similar to `post/brocade/gather/enum_brocade` only access isn't required,
and assumes you already have the file.

Example files for import can be found on git, like [this](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/brocade_08.0.30hT311_ic_icx6430.conf).

## Verification Steps

1. Have a Brocade configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/brocade/brocade_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

  **RHOST**

  Needed for setting services and items to.  This is relatively arbitrary.

  **CONFIG**

  File path to the configuration file.

## Scenarios

```
msf5 > wget https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/brocade_08.0.30hT311_ic_icx6430.conf -o /dev/null -O /tmp/brocade.conf
msf5 > use auxiliary/admin/brocade/brocade_config
msf5 auxiliary(admin/brocade/brocade_config) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(admin/brocade/brocade_config) > set config /tmp/brocade.conf
config => /tmp/brocade.conf
msf5 auxiliary(admin/brocade/brocade_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] password-display is enabled, hashes will be displayed in config
[+] enable password hash $1$QP3H93Wm$uxYAs2HmAK0lQiP3ig5tm.
[+] User brocade of type 8 found with password hash $1$f/uxhovU$dST5lNskZCPQe/5QijULi0.
[+] ENCRYPTED SNMP community $MlVzZCFAbg== with permissions ro
[+] ENCRYPTED SNMP community $U2kyXj1k with permissions rw
[+] Config import successful
[*] Auxiliary module execution completed
```


