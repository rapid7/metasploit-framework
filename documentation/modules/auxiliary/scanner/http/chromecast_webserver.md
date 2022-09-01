This module is a scanner which enumerates Google Chromecast via its HTTP interface (default port 8008).  The WiFi access point the Chromecast is also enumerated.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/chromecast_webserver ```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios

### All 3 of the devices are the 1st generation Google Chromecast (USB stick looking, not circular)

```
msf > use auxiliary/scanner/http/chromecast_webserver 
msf auxiliary(chromecast_webserver) > set threads 10
threads => 10
msf auxiliary(chromecast_webserver) > set verbose true
verbose => true
msf auxiliary(chromecast_webserver) > set rhosts 10.10.10.0/24
rhosts => 10.10.10.0/24
msf auxiliary(chromecast_webserver) > run

[+] 10.10.10.25:8008     - Chromecast "Guest Bedroom" is connected to Rapid7_wifi
[*] Scanned  26 of 256 hosts (10% complete)
[*] Scanned  52 of 256 hosts (20% complete)
[*] Scanned  78 of 256 hosts (30% complete)
[*] Scanned 108 of 256 hosts (42% complete)
[*] Scanned 128 of 256 hosts (50% complete)
[*] Scanned 154 of 256 hosts (60% complete)
[*] Scanned 183 of 256 hosts (71% complete)
[+] 10.10.10.192:8008    - Chromecast "Bedroom" is connected to Rapid7_wep
[+] 10.10.10.196:8008    - Chromecast "cast" is connected to Rapid7_wep
[*] Scanned 213 of 256 hosts (83% complete)
[*] Scanned 232 of 256 hosts (90% complete)
[+] 10.10.10.236:8008    - Chromecast "Basement" is connected to Rapid7_wep
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
