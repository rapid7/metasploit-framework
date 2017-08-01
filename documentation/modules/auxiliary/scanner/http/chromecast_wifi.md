This module is a scanner which enumerates WiFi access points visible from a Google Chromecast via its HTTP interface (default port 8080).  Any WiFi access point the Chromecast is associated with or can be associated with is marked with an `(*)`.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/chromecast_wifi```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios

### All 3 of the devices are the 1st generation Google Chromecast (USB stick looking, not circular)

```
msf > use auxiliary/scanner/http/chromecast_wifi 
msf auxiliary(chromecast_wifi) > set rhosts 10.10.10.0/24
rhosts => 10.10.10.0/24
msf auxiliary(chromecast_wifi) > set threads 20
threads => 20
msf auxiliary(chromecast_wifi) > set verbose true
verbose => true
msf auxiliary(chromecast_wifi) > run

Wireless Access Points from 10.10.10.11
========================================

BSSID              PWR  ENC   CIPHER  AUTH  ESSID
-----              ---  ---   ------  ----  -----
00:11:22:33:44:55  -59  WPA2  CCMP    PSK   Rapid7 (*)
aa:11:22:33:44:66  -71  OPN                 xfinitywifi

[*] Scanned  26 of 256 hosts (10% complete)
[*] Scanned  53 of 256 hosts (20% complete)
[*] Scanned  79 of 256 hosts (30% complete)
[*] Scanned 105 of 256 hosts (41% complete)
[*] Scanned 129 of 256 hosts (50% complete)
[*] Scanned 154 of 256 hosts (60% complete)
Wireless Access Points from 10.10.10.12
=========================================

BSSID              PWR  ENC   CIPHER  AUTH  ESSID
-----              ---  ---   ------  ----  -----
bb:aa:22:33:44:66  -94  WPA   TKIP    PSK   wifi
bb:aa:cc:dd:44:66  -54  WPA2  CCMP    PSK   wifi2 (*)

[*] Scanned 180 of 256 hosts (70% complete)
Wireless Access Points from 10.10.10.16
=========================================

BSSID              PWR  ENC   CIPHER  AUTH  ESSID
-----              ---  ---   ------  ----  -----
bb:aa:cc:dd:44:66  -54  WPA2  CCMP    PSK   wifi2 (*)

[*] Scanned 222 of 256 hosts (86% complete)
Wireless Access Points from 10.10.10.23
=========================================

BSSID              PWR  ENC   CIPHER  AUTH  ESSID
-----              ---  ---   ------  ----  -----
bb:aa:cc:dd:44:66  -63  WPA2  CCMP    PSK   wifi2 (*)
00:11:22:33:44:55  -85  WPA2  CCMP    PSK   Rapid7 (*)

[*] Scanned 241 of 256 hosts (94% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
