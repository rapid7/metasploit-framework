## Vulnerable Application

### General Notes

This module imports a Juniper configuration file into the database.
This is similar to `post/networking/gather/enum_juniper` only access isn't required,
and assumes you already have the file.

### Example Configs

#### JunOS

[JunOS](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ex2200.config)

```
## Last commit: 2016-08-15 13:35:48 UTC by root
version 12.3R7.7;
system {
    host-name h00dieJuniperEx2200;
    root-authentication {
        encrypted-password "$1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E."; ## SECRET-DATA
    }
    login {
        user newuser {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password "$1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/"; ## SECRET-DATA
            }
        }
        user newuser2 {
            uid 2002;
            class operator;
            authentication {
                encrypted-password "$1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0"; ## SECRET-DATA
            }
        }
        user newuser3 {
            uid 2003;
            class read-only;
            authentication {
                encrypted-password "$1$1.YvKzUY$dcAj99KngGhFZTpxGjA93."; ## SECRET-DATA
            }
        }
        user newuser4 {
            uid 2004;
            class unauthorized;
            authentication {
                encrypted-password "$1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/"; ## SECRET-DATA
            }
        }
    }
    services {
        ssh {
            root-login allow;
        }
        web-management {
            http;
        }
        dhcp {
            traceoptions {
                file dhcp_logfile;
                level all;
                flag all;
            }
            pool 192.168.10.0/24 {
                address-range low 192.168.10.2 high 192.168.10.254;
            }
        }
    }
    syslog {
        user * {
            any emergency;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
    }
}
chassis {
    alarm {
        management-ethernet {
            link-down ignore;
        }
    }
    auto-image-upgrade;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.3/32;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 192.168.1.4/32;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 192.168.1.5/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/4 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/5 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/6 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/7 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/8 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/9 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/10 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/11 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/12 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/13 {
        unit 0 {
 ## Last commit: 2016-08-15 13:35:48 UTC by root
version 12.3R7.7;
system {
    host-name h00dieJuniperEx2200;
    root-authentication {
        encrypted-password "$1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E."; ## SECRET-DATA
    }
    login {
        user newuser {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password "$1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/"; ## SECRET-DATA
            }
        }
        user newuser2 {
            uid 2002;
            class operator;
            authentication {
                encrypted-password "$1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0"; ## SECRET-DATA
            }
        }
        user newuser3 {
            uid 2003;
            class read-only;
            authentication {
                encrypted-password "$1$1.YvKzUY$dcAj99KngGhFZTpxGjA93."; ## SECRET-DATA
            }
        }
        user newuser4 {
            uid 2004;
            class unauthorized;
            authentication {
                encrypted-password "$1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/"; ## SECRET-DATA
            }
        }
    }
    services {
        ssh {
            root-login allow;
        }
        web-management {
            http;
        }
        dhcp {
            traceoptions {
                file dhcp_logfile;
                level all;
                flag all;
            }
            pool 192.168.10.0/24 {
                address-range low 192.168.10.2 high 192.168.10.254;
            }
        }
    }
    syslog {
        user * {
            any emergency;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
    }
}
chassis {
    alarm {
        management-ethernet {
            link-down ignore;
        }
    }
    auto-image-upgrade;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.3/32;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 192.168.1.4/32;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 192.168.1.5/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/4 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/5 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/6 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/7 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/8 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/9 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/10 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/11 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/12 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/13 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/14 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/15 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/16 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/17 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/18 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/19 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/20 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/21 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/22 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/23 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/24 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/25 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/26 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/27 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/28 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/29 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/30 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/31 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/32 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/33 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/34 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/35 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/36 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/37 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/38 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/39 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/40 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/41 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/42 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/43 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/44 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/45 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/46 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/47 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/0 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/1 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/2 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/3 {
        unit 0 {
            family ethernet-switching;
        }
    }
    me0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
    pp0 {
        unit 0 {
            ppp-options {
                pap {
                    local-name "'pap_username'";
                    local-password "$9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR"; ## SECRET-DATA
                }
            }
        }
    }
    st0 {
        unit 1;
    }
    vlan {
        unit 0 {
            family inet {
                dhcp {
                    vendor-id Juniper-ex2200-48t-4g;
                }
            }
        }
    }
}
snmp {
    name "snmp name";
    description "snmp description";
    location basement;
    contact admin;
    view jweb-view-all {
        oid .1 include;
    }
    community read {
        authorization read-only;
    }
    community write {
        view jweb-view-all;
        authorization read-write;
    }
    community public {
        authorization read-only;
    }
    community private {
        authorization read-write;
    }
    community secretsauce {
        authorization read-write;
    }
    community "hello there" {
        authorization read-write;
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 192.168.1.254;
    }
}
protocols {
    igmp-snooping {
        vlan all;
    }
    rstp;
    lldp {
        interface all;
    }
    lldp-med {
        interface all;
    }
}
access {
    radius-server {
        1.1.1.1 secret "$9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV"; ## SECRET-DATA
    }
}
ethernet-switching-options {
    storm-control {
        interface all;
    }
}
vlans {
    default {
        l3-interface vlan.0;
    }
}           family ethernet-switching;
        }
    }
    ge-0/0/14 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/15 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/16 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/17 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/18 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/19 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/20 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/21 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/22 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/23 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/24 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/25 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/26 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/27 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/28 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/29 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/30 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/31 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/32 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/33 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/34 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/35 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/36 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/37 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/38 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/39 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/40 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/41 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/42 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/43 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/44 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/45 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/46 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/0/47 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/0 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/1 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/2 {
        unit 0 {
            family ethernet-switching;
        }
    }
    ge-0/1/3 {
        unit 0 {
            family ethernet-switching;
        }
    }
    me0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
    pp0 {
        unit 0 {
            ppp-options {
                pap {
                    local-name "'pap_username'";
                    local-password "$9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR"; ## SECRET-DATA
                }
            }
        }
    }
    st0 {
        unit 1;
    }
    vlan {
        unit 0 {
            family inet {
                dhcp {
                    vendor-id Juniper-ex2200-48t-4g;
                }
            }
        }
    }
}
snmp {
    name "snmp name";
    description "snmp description";
    location basement;
    contact admin;
    view jweb-view-all {
        oid .1 include;
    }
    community read {
        authorization read-only;
    }
    community write {
        view jweb-view-all;
        authorization read-write;
    }
    community public {
        authorization read-only;
    }
    community private {
        authorization read-write;
    }
    community secretsauce {
        authorization read-write;
    }
    community "hello there" {
        authorization read-write;
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 192.168.1.254;
    }
}
protocols {
    igmp-snooping {
        vlan all;
    }
    rstp;
    lldp {
        interface all;
    }
    lldp-med {
        interface all;
    }
}
access {
    radius-server {
        1.1.1.1 secret "$9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV"; ## SECRET-DATA
    }
}
ethernet-switching-options {
    storm-control {
        interface all;
    }
}
vlans {
    default {
        l3-interface vlan.0;
    }
}
```

#### ScreenOS

[screenos](https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ssg5_screenos.conf)

```
unset key protection enable
set clock timezone 0
set vrouter trust-vr sharable
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
unset auto-route-export
exit
set alg appleichat enable
unset alg appleichat re-assembly enable
set alg sctp enable
set auth-server "Local" id 0
set auth-server "Local" server-name "Local"
set auth default auth server "Local"
set auth radius accounting port 1646
set admin name "netscreen"
set admin password "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn"
set admin auth web timeout 10
set admin auth dial-in timeout 3
set admin auth server "Local"
set admin format dos
set zone "Trust" vrouter "trust-vr"
set zone "Untrust" vrouter "trust-vr"
set zone "DMZ" vrouter "trust-vr"
set zone "VLAN" vrouter "trust-vr"
set zone "Untrust-Tun" vrouter "trust-vr"
set zone "Trust" tcp-rst 
set zone "Untrust" block 
unset zone "Untrust" tcp-rst 
set zone "MGT" block 
unset zone "V1-Trust" tcp-rst 
unset zone "V1-Untrust" tcp-rst 
set zone "DMZ" tcp-rst 
unset zone "V1-DMZ" tcp-rst 
unset zone "VLAN" tcp-rst 
set zone "Untrust" screen tear-drop
set zone "Untrust" screen syn-flood
set zone "Untrust" screen ping-death
set zone "Untrust" screen ip-filter-src
set zone "Untrust" screen land
set zone "V1-Untrust" screen tear-drop
set zone "V1-Untrust" screen syn-flood
set zone "V1-Untrust" screen ping-death
set zone "V1-Untrust" screen ip-filter-src
set zone "V1-Untrust" screen land
set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/1" zone "DMZ"
set interface "bgroup0" zone "Trust"
set interface bgroup0 port ethernet0/2
set interface bgroup0 port ethernet0/3
set interface bgroup0 port ethernet0/4
set interface bgroup0 port ethernet0/5
set interface bgroup0 port ethernet0/6
unset interface vlan1 ip
set interface bgroup0 ip 192.168.1.1/24
set interface bgroup0 nat
unset interface vlan1 bypass-others-ipsec
unset interface vlan1 bypass-non-ip
set interface bgroup0 ip manageable
set interface ethernet0/0 dhcp client enable
set interface ethernet0/0 dhcp client settings autoconfig
set interface "serial0/0" modem settings "USR" init "AT&F"
set interface "serial0/0" modem settings "USR" active
set interface "serial0/0" modem speed 115200
set interface "serial0/0" modem retry 3
set interface "serial0/0" modem interval 10
set interface "serial0/0" modem idle-time 10
set ip tftp retry 30
set ip tftp timeout 30
set flow tcp-mss
unset flow no-tcp-seq-check
set flow tcp-syn-check
unset flow tcp-syn-bit-check
set flow reverse-route clear-text prefer
set flow reverse-route tunnel always
set pki authority default scep mode "auto"
set pki x509 default cert-path partial
set user "testuser" uid 1
set user "testuser" type auth
set user "testuser" hash-password "02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE="
set user "testuser" enable
set crypto-policy
exit
set ike respond-bad-spi 1
set ike ikev2 ike-sa-soft-lifetime 60
unset ike ikeid-enumeration
unset ike dos-protection
unset ipsec access-session enable
set ipsec access-session maximum 5000
set ipsec access-session upper-threshold 0
set ipsec access-session lower-threshold 0
set ipsec access-session dead-p2-sa-timeout 0
unset ipsec access-session log-error
unset ipsec access-session info-exch-connected
unset ipsec access-session use-error-log
set url protocol websense
exit
set policy id 1 from "Trust" to "Untrust"  "Any" "Any" "ANY" permit 
set policy id 1
exit
set nsmgmt bulkcli reboot-timeout 60
set ssh version v2
set config lock timeout 5
unset license-key auto-update
set telnet client enable
set snmp port listen 161
set snmp port trap 162
set snmpv3 local-engine id "0162122013002408"
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
unset add-default-route
exit
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
exit
```

## Verification Steps

1. Have a Juniper configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/juniper_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `set action junos`
7. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

### Action

`JUNOS` for JunOS config file, and `SCREENOS` for ScreenOS config file.

## Scenarios

### JunOS

```
root@metasploit-dev:~/metasploit-framework# wget -o /dev/null -O /tmp/juniper_ex2200.config https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ex2200.config
root@metasploit-dev:~/metasploit-framework# ./msfconsole 

[*] Starting persistent handler(s)...
msf5 > use auxiliary/admin/networking/gather/juniper_config
msf5 auxiliary(admin/networking/gather/juniper_config) > set config /tmp/juniper_ex2200.config
config => /tmp/juniper_ex2200.config
msf5 auxiliary(admin/networking/gather/juniper_config) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(admin/networking/gather/juniper_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
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
[+] Config import successful
[*] Auxiliary module execution completed
```

### ScreenOS

```
root@metasploit-dev:~/metasploit-framework# wget -o /dev/null -O /tmp/screenos.conf https://raw.githubusercontent.com/h00die/MSF-Testing-Scripts/master/juniper_ssg5_screenos.conf
root@metasploit-dev:~/metasploit-framework# ./msfconsole 

[*] Starting persistent handler(s)...
msf5 > use auxiliary/admin/networking/gather/juniper_config
msf5 auxiliary(admin/networking/gather/juniper_config) > set config /tmp/screenos.conf
config => /tmp/screenos.conf
msf5 auxiliary(admin/networking/gather/juniper_config) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(admin/networking/gather/juniper_config) > set action SCREENOS
action => SCREENOS
msf5 auxiliary(admin/networking/gather/juniper_config) > run
[*] Running module against 127.0.0.1

[*] Importing config
[+] Admin user netscreen found with password hash nKVUM2rwMUzPcrkG5sWIHdCtqkAibn
[+] User 1 named testuser found with password hash auth. Enable permission: 02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=
[+] Config import successful
[*] Auxiliary module execution completed
```
