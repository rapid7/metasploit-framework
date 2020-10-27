## Vulnerable Application

### General Notes

This module imports a VyOS configuration file into the database.
This is similar to `post/networking/gather/enum_vyos` only access isn't required,
and assumes you already have the file.

VyOS is available to download from [VyOS.io](https://downloads.vyos.io/).

Example config file:

#### VyOS 1.3

```
interfaces {
    ethernet eth0 {
        address 10.10.10.10/24
        description "desc two"
        hw-id 00:0c:29:ab:ce:16
    }
    ethernet eth1 {
        hw-id 00:0c:29:ab:ce:20
    }
    loopback lo {
    }
}
service {
    snmp {
        community ro {
            authorization ro
        }
        community write {
            authorization rw
        }
    }
}
system {
    config-management {
        commit-revisions 100
    }
    console {
        device ttyS0 {
            speed 115200
        }
    }
    host-name vyos
    login {
        user vyos {
            authentication {
                encrypted-password $6$km/6j4hX0Ayo$dk2z5LeUOayHopgLGZJII0whBMidnvsd4LfT6LcIcR9ReabX0kcXjZOlmmqDGWuo1FvpnV.X2IRl5NeEZpuI31
                plaintext-password ""
            }
        }
    }
    ntp {
        server 0.pool.ntp.org {
        }
        server 1.pool.ntp.org {
        }
        server 2.pool.ntp.org {
        }
    }
    syslog {
        global {
            facility all {
                level info
            }
            facility protocols {
                level debug
            }
        }
    }
}
// Warning: Do not remove the following line.
// vyos-config-version: "broadcast-relay@1:cluster@1:config-management@1:conntrack@1:conntrack-sync@1:dhcp-relay@2:dhcp-server@5:dhcpv6-server@1:dns-forwarding@3:firewall@5:https@2:interfaces@12:ipoe-server@1:ipsec@5:l2tp@3:lldp@1:mdns@1:nat@5:ntp@1:pppoe-server@4:pptp@2:qos@1:quagga@6:salt@1:snmp@2:ssh@2:sstp@2:system@18:vrrp@2:vyos-accel-ppp@2:wanloadbalance@3:webgui@1:webproxy@2:zone-policy@1"
// Release version: 1.3-rolling-202008270118
```

#### VyOS 1.1.8
```
interfaces {
    ethernet eth0 {
        description "eth0 main"
        duplex auto
        hw-id 00:0c:29:f4:45:0a
        smp_affinity auto
        speed auto
        vif 90 {
            address dhcp
        }
    }
    ethernet eth1 {
        address 10.10.10.10/24
        duplex auto
        hw-id 00:0c:29:f4:45:14
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}
service {
    snmp {
        community ro {
            authorization ro
        }
        community write {
            authorization rw
        }
    }
}
system {
    config-management {
        commit-revisions 20
    }
    console {
    }
    host-name vyos118
    login {
        user jsmith {
            authentication {
                encrypted-password $6$b/9HkzK14DtQm3W$UL5z9yGDoX8j13meRLFEGYkn8popOtCa91wwg8qxOFIfQcWBuXQDDiy8NhdPhpnYieBykj1ddytJAwU6C4mrH1
                plaintext-password ""
            }
            full-name "john smith"
            level operator
        }
        user vyos {
            authentication {
                encrypted-password $1$hTBP1zOx$M0WnYPshI2piRc7.XnwBU0
                plaintext-password ""
            }
            level admin
        }
    }
    ntp {
        server 0.pool.ntp.org {
        }
        server 1.pool.ntp.org {
        }
        server 2.pool.ntp.org {
        }
    }
    package {
        auto-sync 1
        repository community {
            components main
            distribution helium
            password ""
            url http://packages.vyos.net/vyos
            username ""
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone UTC
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "cluster@1:config-management@1:conntrack-sync@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@4:nat@4:qos@1:quagga@2:system@6:vrrp@1:wanloadbalance@3:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: VyOS 1.1.8 */
```

## Verification Steps

1. Have a VyOS configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/vyos_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

## Scenarios

### VyOS 1.1.8

```
msf6 > use auxiliary/admin/networking/vyos_config 
msf6 auxiliary(admin/networking/vyos_config) > set config /tmp/vyos.config
config => /tmp/vyos.config
msf6 auxiliary(admin/networking/vyos_config) > set verbose true
verbose => true
msf6 auxiliary(admin/networking/vyos_config) > run
[-] Auxiliary failed: Msf::OptionValidateError One or more options failed to validate: RHOSTS.
msf6 auxiliary(admin/networking/vyos_config) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(admin/networking/vyos_config) > run
[*] Running module against 1.1.1.1

[*] Importing config
[+] Config saved to: /home/h00die/.msf4/loot/20200920154519_default_1.1.1.1_vyos.config_295168.txt
[+] 1.1.1.1:22 Username 'jsmith' with level 'operator' with hash $6$b/9HkzK14DtQm3W$UL5z9yGDoX8j13meRLFEGYkn8popOtCa91wwg8qxOFIfQcWBuXQDDiy8NhdPhpnYieBykj1ddytJAwU6C4mrH1
[+] 1.1.1.1:22 Username 'vyos' with level 'admin' with hash $1$hTBP1zOx$M0WnYPshI2piRc7.XnwBU0
[+] 1.1.1.1:22 SNMP Community 'ro' with ro access
[+] 1.1.1.1:22 SNMP Community 'write' with rw access
[+] 1.1.1.1:22 Hostname: vyos118
[+] 1.1.1.1:22 OS Version: VyOS 1.1.8
[+] 1.1.1.1:22 Interface eth1 (00:0c:29:f4:45:14) - 10.10.10.10
[+] Config import successful
[*] Auxiliary module execution completed
```


