## Vulnerable Application

### General Notes

This module imports a Brocade configuration file into the database.
This is similar to `post/networking/gather/enum_brocade` only access isn't required,
and assumes you already have the file.

### Example Config

Example files for import can be found on git, like
[this](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/brocade_08.0.30hT311_ic_icx6430.conf).

```
!
Startup-config data location is flash memory
!
Startup configuration:
!
ver 08.0.20T311
!
stack unit 1
  module 1 icx6430-24-port-management-module
  module 2 icx6430-sfp-4port-4g-module
!
!
!
!
!
!
!
!
aaa authentication web-server default local
aaa authentication login default local
enable password-display
enable super-user-password 8 $1$QP3H93Wm$uxYAs2HmAK0lQiP3ig5tm.
ip address 2.2.2.2 255.255.255.0 dynamic
ip dns server-address 1.1.1.1
ip default-gateway 1.1.1.1
!
username brocade password 8 $1$f/uxhovU$dST5lNskZCPQe/5QijULi0
username test password 8 $1$qKOcZizM$ySW1EyiUpKSHw9MT4PZ11.
snmp-server community 2 $MlVzZCFAbg== ro
snmp-server community 2 $U2kyXj1k rw
!
!
interface ethernet 1/1/1
 speed-duplex 1000-full-master
!
interface ethernet 1/1/2
 speed-duplex 1000-full-master
!
interface ethernet 1/1/3
 speed-duplex 1000-full-master
!
interface ethernet 1/1/4
 speed-duplex 1000-full-master
!
interface ethernet 1/1/5
 speed-duplex 1000-full-master
!
interface ethernet 1/1/6
 speed-duplex 1000-full-master
!
interface ethernet 1/1/7
 speed-duplex 1000-full-master
!
interface ethernet 1/1/8
 speed-duplex 1000-full-master
!
interface ethernet 1/1/9
 speed-duplex 1000-full-master
!
interface ethernet 1/1/10
 speed-duplex 1000-full-master
!
interface ethernet 1/1/11
 speed-duplex 1000-full-master
!
interface ethernet 1/1/12
 speed-duplex 1000-full-master
!
interface ethernet 1/1/13
 speed-duplex 1000-full-master
!
interface ethernet 1/1/14
 speed-duplex 1000-full-master
!
interface ethernet 1/1/15
 speed-duplex 1000-full-master
!
interface ethernet 1/1/16
 speed-duplex 1000-full-master
!
interface ethernet 1/1/17
 speed-duplex 1000-full-master
!
interface ethernet 1/1/18
 speed-duplex 1000-full-master
!
interface ethernet 1/1/19
 speed-duplex 1000-full-master
!
interface ethernet 1/1/20
 speed-duplex 1000-full-master
!
interface ethernet 1/1/21
 speed-duplex 1000-full-master
!
interface ethernet 1/1/22
 speed-duplex 1000-full-master
!
interface ethernet 1/1/23
 speed-duplex 1000-full-master
 no spanning-tree
!
interface ethernet 1/1/24
 speed-duplex 1000-full-master
 no spanning-tree
!
!
!
!
!
!
!
!
end
```

## Verification Steps

1. Have a Brocade configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/brocade_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

## Scenarios

```
msf5 > wget https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/brocade_08.0.30hT311_ic_icx6430.conf -o /dev/null -O /tmp/brocade.conf
msf5 > use auxiliary/admin/networking/brocade_config
msf5 auxiliary(admin/networking/brocade_config) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(admin/networking/brocade_config) > set config /tmp/brocade.conf
config => /tmp/brocade.conf
msf5 auxiliary(admin/networking/brocade_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] password-display is enabled, hashes will be displayed in config
[+] enable password hash $1$QP3H93Wm$uxYAs2HmAK0lQiP3ig5tm.
[+] User brocade of type 8 found with password hash $1$f/uxhovU$dST5lNskZCPQe/5QijULi0.
[+] ENCRYPTED SNMP community $MlVzZCFAbg== with permissions ro
[+] ENCRYPTED SNMP community $U2kyXj1k with permissions rw
[+] Config import successful
[*] Auxiliary module execution completed
```


