## General Notes

This module imports a Cisco configuration file into the database.
This is similar to `post/cisco/gather/enum_cisco` only access isn't required,
and assumes you already have the file.

Example files for import can be found on git, like [this](https://raw.githubusercontent.com/GaetanLongree/MASI-ProjetAvanceReseau/3cf1d9a93828d5f44ee1bc4e4c01411e416892c5/Los%20Angeles/LA_EDGE_D.txt)
or from [Cisco](https://www.cisco.com/en/US/docs/routers/access/800/850/software/configuration/guide/sampconf.html).

## Verification Steps

1. Have a Cisco configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/cisco/cisco_config`
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
root@metasploit-dev:~/metasploit-framework# wget https://raw.githubusercontent.com/GaetanLongree/MASI-ProjetAvanceReseau/3cf1d9a93828d5f44ee1bc4e4c01411e416892c5/Los%20Angeles/LA_EDGE_D.txt -O /tmp/LA_EDGE_D.txt -o /dev/null

root@metasploit-dev:~/metasploit-framework# ./msfconsole 

[*] Starting persistent handler(s)...
msf5 > use auxiliary/admin/cisco/cisco_config 
msf5 auxiliary(admin/cisco/cisco_config) > set config /tmp/LA_EDGE_D.txt
config => /tmp/LA_EDGE_D.txt
msf5 auxiliary(admin/cisco/cisco_config) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(admin/cisco/cisco_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] 127.0.0.1:22 MD5 Encrypted Enable Password: $1$mERr$DWwx4W/5HXD2oail62IeB1
[+] 127.0.0.1:22 Username 'Waldo' with MD5 Encrypted Password: $1$mERr$DWwx4W/5HXD2oail62IeB1
[+] Config import successful
[*] Auxiliary module execution completed
```

