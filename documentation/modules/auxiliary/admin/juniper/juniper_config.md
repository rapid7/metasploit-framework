## General Notes

This module imports a Juniper configuration file into the database.
This is similar to `post/juniper/gather/enum_juniper` only access isn't required,
and assumes you already have the file.

Example files for import can be found on git, like [this (junos)](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ex2200.config)
or [this (screenos)](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ssg5_screenos.conf).

## Verification Steps

1. Have a Juniper configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/juniper/juniper_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `set action junos`
7. `run`

## Options

  **RHOST**

  Needed for setting services and items to.  This is relatively arbitrary.

  **CONFIG**

  File path to the configuration file.

  **Action**

  `JUNOS` for JunOS config file, and `SCREENOS` for ScreenOS config file.

## Scenarios

### JunOS

```
root@metasploit-dev:~/metasploit-framework# wget -o /dev/null -O /tmp/juniper_ex2200.config https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ex2200.config
root@metasploit-dev:~/metasploit-framework# ./msfconsole 

[*] Starting persistent handler(s)...
msf5 > use auxiliary/admin/juniper/gather/juniper_config
msf5 auxiliary(admin/juniper/gather/juniper_config) > set config /tmp/juniper_ex2200.config
config => /tmp/juniper_ex2200.config
msf5 auxiliary(admin/juniper/gather/juniper_config) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(admin/juniper/gather/juniper_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] root password hash: $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.
[+] User 2000 named newuser in group super-user found with password hash $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/.
[+] User 2002 named newuser2 in group operator found with password hash $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0.
[+] User 2003 named newuser3 in group read-only found with password hash $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93..
[+] User 2004 named newuser4 in group unauthorized found with password hash $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/.
[+] SNMP community read with permissions read-only
[+] SNMP community public with permissions read-only
[+] SNMP community private with permissions read-write
[+] SNMP community secretsauce with permissions read-write
[+] SNMP community hello there with permissions read-write
[+] radius server 1.1.1.1 password hash: $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV
[+] PPTP username 'pap_username' hash $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR via PAP
[+] Config import successful
[*] Auxiliary module execution completed
```

### ScreenOS

```
root@metasploit-dev:~/metasploit-framework# wget -o /dev/null -O /tmp/screenos.conf https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ssg5_screenos.conf
root@metasploit-dev:~/metasploit-framework# ./msfconsole 

[*] Starting persistent handler(s)...
msf5 > use auxiliary/admin/juniper/gather/juniper_config
msf5 auxiliary(admin/juniper/gather/juniper_config) > set config /tmp/screenos.conf
config => /tmp/screenos.conf
msf5 auxiliary(admin/juniper/gather/juniper_config) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(admin/juniper/gather/juniper_config) > set action SCREENOS
action => SCREENOS
msf5 auxiliary(admin/juniper/gather/juniper_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] Admin user netscreen found with password hash nKVUM2rwMUzPcrkG5sWIHdCtqkAibn
[+] User 1 named testuser found with password hash auth. Enable permission: 02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=
[+] Config import successful
[*] Auxiliary module execution completed
```

