## Vulnerable Application

### General Notes

This module imports an F5 configuration file into the database.
This is similar to `post/networking/gather/enum_f5` only access isn't required,
and assumes you already have the file.

### Example Config

```
#TMSH-VERSION: 15.1.0.2

cm cert /Common/dtca-bundle.crt {
    cache-path /config/filestore/files_d/Common_d/trust_certificate_d/:Common:dtca-bundle.crt_62970_3
    checksum SHA1:1310:d1e052507e0ec1a274848374ff904ae8548d7dd2
    revision 3
}
cm cert /Common/dtca.crt {
    cache-path /config/filestore/files_d/Common_d/trust_certificate_d/:Common:dtca.crt_62966_3
    checksum SHA1:1310:d1e052507e0ec1a274848374ff904ae8548d7dd2
    revision 3
}
cm cert /Common/dtdi.crt {
    cache-path /config/filestore/files_d/Common_d/trust_certificate_d/:Common:dtdi.crt_62962_3
    checksum SHA1:1285:0f4ddae3808474c70911f43725c7cfdb46aa4430
    revision 3
}
cm device /Common/f5bigip.home.com {
    active-modules { "BIG-IP, VE Trial|VTFLRXF-LFSIQYY|Rate Shaping|External Interface and Network HSM, VE|SDN Services, VE|SSL, Forward Proxy, VE|BIG-IP VE, Multicast Routing|APM, Limited|SSL, VE|DNS (1K QPS), VE|Routing Bundle, VE|ASM, VE|Crytpo Offload, VE, Tier 1 (25M - 200M)|Max Compression, VE|AFM, VE|DNSSEC|Anti-Virus Checks|Base Endpoint Security Checks|Firewall Checks|Network Access|Secure Virtual Keyboard|APM, Web Application|Machine Certificate Checks|Protected Workspace|Remote Desktop|App Tunnel|VE, Carrier Grade NAT (AFM ONLY)|PSM, VE" }
    base-mac aa:aa:aa:aa:aa:aa
    build 0.0.9
    cert /Common/dtdi.crt
    chassis-id 564dcf79-53ce-3494-3217671849c7
    configsync-ip 10.10.10.222
    edition "Point Release 2"
    hostname f5bigip.home.com
    key /Common/dtdi.key
    management-ip 2.2.2.2
    marketing-name "BIG-IP Virtual Edition"
    platform-id Z100
    product BIG-IP
    self-device true
    time-zone America/Los_Angeles
    version 15.1.0.2
}
cm device-group /Common/device_trust_group {
    auto-sync enabled
    devices {
        /Common/f5bigip.home.com { }
    }
    hidden true
    network-failover disabled
}
cm device-group /Common/gtm {
    devices {
        /Common/f5bigip.home.com { }
    }
    hidden true
    network-failover disabled
}
cm key /Common/dtca.key {
    cache-path /config/filestore/files_d/Common_d/trust_certificate_key_d/:Common:dtca.key_62968_3
    checksum SHA1:1704:f274958ad619b0c70d8ccc4f7c5ae199061464e6
    revision 3
}
cm key /Common/dtdi.key {
    cache-path /config/filestore/files_d/Common_d/trust_certificate_key_d/:Common:dtdi.key_62964_3
    checksum SHA1:1704:97eeb5aedee76b3c21e6d735604a092e830ef6c2
    revision 3
}
cm traffic-group /Common/traffic-group-1 {
    unit-id 1
}
cm traffic-group /Common/traffic-group-local-only { }
cm trust-domain /Common/Root {
    ca-cert /Common/dtca.crt
    ca-cert-bundle /Common/dtca-bundle.crt
    ca-devices { /Common/f5bigip.home.com }
    ca-key /Common/dtca.key
    guid fe0ee274-0355-4940-acc7000c291849c7
    status standalone
    trust-group /Common/device_trust_group
}
net interface 1.1 {
    media-fixed 10000T-FD
}
net interface 1.2 {
    media-fixed 10000T-FD
}
net interface 1.3 {
    media-fixed 10000T-FD
}
net port-list /Common/_sys_self_allow_tcp_defaults {
    ports {
        22 { }
        53 { }
        161 { }
        443 { }
        1029-1043 { }
        4353 { }
    }
}
net port-list /Common/_sys_self_allow_udp_defaults {
    ports {
        53 { }
        161 { }
        520 { }
        1026 { }
        4353 { }
    }
}
net route-domain /Common/0 {
    id 0
    vlans {
        /Common/http-tunnel
        /Common/socks-tunnel
        /Common/internal
    }
}
net self /Common/10.10.10.223 {
    address 10.10.10.223/8
    allow-service {
        default
    }
    traffic-group /Common/traffic-group-1
    vlan /Common/internal
}
net self /Common/10.10.10.222 {
    address 10.10.10.222/8
    allow-service {
        default
    }
    traffic-group /Common/traffic-group-local-only
    vlan /Common/internal
}
net self-allow {
    defaults {
        igmp:0
        ospf:0
        pim:0
        tcp:161
        tcp:22
        tcp:4353
        tcp:443
        tcp:53
        udp:1026
        udp:161
        udp:4353
        udp:520
        udp:53
    }
}
net stp /Common/cist { }
net vlan /Common/internal {
    tag 4094
}
net fdb tunnel /Common/http-tunnel { }
net fdb tunnel /Common/socks-tunnel { }
net fdb vlan /Common/internal { }
net tunnels tunnel /Common/http-tunnel {
    description "Tunnel for http-explicit profile"
    profile /Common/tcp-forward
}
net tunnels tunnel /Common/socks-tunnel {
    description "Tunnel for socks profile"
    profile /Common/tcp-forward
}
security device-id attribute /Common/att01 {
    id 1
}
security device-id attribute /Common/att02 {
    id 2
}
security device-id attribute /Common/att03 {
    id 3
}
security device-id attribute /Common/att04 {
    id 4
}
security device-id attribute /Common/att05 {
    id 5
}
security device-id attribute /Common/att06 {
    id 6
}
security device-id attribute /Common/att07 {
    id 7
}
security device-id attribute /Common/att08 {
    id 8
}
security device-id attribute /Common/att09 {
    id 9
}
security device-id attribute /Common/att10 {
    id 10
}
security device-id attribute /Common/att11 {
    id 11
}
security device-id attribute /Common/att12 {
    id 12
}
security device-id attribute /Common/att13 {
    id 13
}
security device-id attribute /Common/att14 {
    id 14
}
security device-id attribute /Common/att15 {
    id 15
}
security device-id attribute /Common/att16 {
    id 16
}
security device-id attribute /Common/att17 {
    id 17
}
security device-id attribute /Common/att18 {
    id 18
}
security device-id attribute /Common/att19 {
    id 19
}
security device-id attribute /Common/att20 {
    id 20
}
security device-id attribute /Common/att21 {
    id 21
}
security device-id attribute /Common/att22 {
    id 22
}
security device-id attribute /Common/att23 {
    id 23
}
security device-id attribute /Common/att24 {
    id 24
}
security device-id attribute /Common/att25 {
    id 25
}
security device-id attribute /Common/att26 {
    id 26
}
security device-id attribute /Common/att27 {
    id 27
}
security device-id attribute /Common/att28 {
    id 28
}
security device-id attribute /Common/att29 {
    id 29
}
security device-id attribute /Common/att30 {
    id 30
}
security device-id attribute /Common/att31 {
    id 31
}
security device-id attribute /Common/att32 {
    id 32
}
security device-id attribute /Common/att33 {
    id 33
}
security device-id attribute /Common/att34 {
    id 34
}
security device-id attribute /Common/att35 {
    id 35
}
security device-id attribute /Common/att36 {
    id 36
}
security device-id attribute /Common/att37 {
    id 37
}
security device-id attribute /Common/att38 {
    id 38
}
security device-id attribute /Common/att39 {
    id 39
}
security firewall config-entity-id /Common/uuid_entity_id {
    entity-id 3346813779321352940
}
security firewall port-list /Common/_sys_self_allow_tcp_defaults {
    ports {
        22 { }
        53 { }
        161 { }
        443 { }
        1029-1043 { }
        4353 { }
    }
}
security firewall port-list /Common/_sys_self_allow_udp_defaults {
    ports {
        53 { }
        161 { }
        520 { }
        1026 { }
        4353 { }
    }
}
security firewall rule-list /Common/_sys_self_allow_all {
    rules {
        _sys_allow_all {
            action accept
            ip-protocol any
        }
    }
}
security firewall rule-list /Common/_sys_self_allow_defaults {
    rules {
        _sys_allow_tcp_defaults {
            action accept
            ip-protocol tcp
            destination {
                port-lists {
                    /Common/_sys_self_allow_tcp_defaults
                }
            }
        }
        _sys_allow_udp_defaults {
            action accept
            ip-protocol udp
            destination {
                port-lists {
                    /Common/_sys_self_allow_udp_defaults
                }
            }
        }
        _sys_allow_ospf_defaults {
            action accept
            ip-protocol ospf
        }
        _sys_allow_pim_defaults {
            action accept
            ip-protocol pim
        }
        _sys_allow_igmp_defaults {
            action accept
            ip-protocol igmp
        }
    }
}
security firewall rule-list /Common/_sys_self_allow_management {
    rules {
        _sys_allow_ssh {
            action accept
            ip-protocol tcp
            destination {
                ports {
                    22 { }
                }
            }
        }
        _sys_allow_web {
            action accept
            ip-protocol tcp
            destination {
                ports {
                    443 { }
                }
            }
        }
    }
}
security ip-intelligence policy /Common/ip-intelligence { }
security shared-objects port-list /Common/_sys_self_allow_tcp_defaults {
    ports {
        22 { }
        53 { }
        161 { }
        443 { }
        1029-1043 { }
        4353 { }
    }
}
security shared-objects port-list /Common/_sys_self_allow_udp_defaults {
    ports {
        53 { }
        161 { }
        520 { }
        1026 { }
        4353 { }
    }
}
sys dns {
    description configured-by-dhcp
    name-servers { 192.168.2.40 9.9.9.9 }
    search { ragedomain }
}
sys folder / {
    device-group none
    hidden false
    inherited-devicegroup false
    inherited-traffic-group false
    traffic-group /Common/traffic-group-1
}
sys folder /Common {
    device-group none
    hidden false
    inherited-devicegroup true
    inherited-traffic-group true
    traffic-group /Common/traffic-group-1
}
sys folder /Common/Drafts {
    device-group none
    hidden false
    inherited-devicegroup true
    inherited-traffic-group true
    traffic-group /Common/traffic-group-1
}
sys global-settings {
    hostname f5bigip.home.com
}
sys management-dhcp /Common/sys-mgmt-dhcp-config {
    request-options { subnet-mask broadcast-address routers domain-name domain-name-servers host-name ntp-servers interface-mtu }
}
sys provision ltm {
    level nominal
}
sys snmp {
    agent-addresses { tcp6:161 udp6:161 }
    communities {
        /Common/comm-public {
            community-name public
            source default
        }
    }
    disk-monitors {
        /Common/root {
            minspace 2000
            path /
        }
        /Common/var {
            minspace 10000
            path /var
        }
    }
    process-monitors {
        /Common/bigd {
            max-processes infinity
            process bigd
        }
        /Common/chmand {
            process chmand
        }
        /Common/httpd {
            max-processes infinity
            process httpd
        }
        /Common/mcpd {
            process mcpd
        }
        /Common/sod {
            process sod
        }
        /Common/tmm {
            max-processes infinity
            process tmm
        }
    }
}
sys dynad settings {
    development-mode false
}
sys fpga firmware-config {
    type standard-balanced-fpga
}
sys sflow global-settings http { }
sys sflow global-settings vlan { }
sys turboflex profile-config {
    type turboflex-adc
}
```

## Verification Steps

1. Have an F5 configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/f5_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

## Scenarios

### F5 Big-IP 15.1.0.2 (virtual on ESXi)

```
resource (f5.rb)> use auxiliary/admin/networking/f5_config
resource (f5.rb)> set config /home/h00die/Downloads/f5_config.txt
config => /home/h00die/Downloads/f5_config.txt
resource (f5.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
resource (f5.rb)> set verbose true
verbose => true
resource (f5.rb)> run
[*] Running module against 127.0.0.1
[*] Importing config
[+] 127.0.0.1:22 SNMP Community 'public' with RO access
[+] 127.0.0.1:22 Hostname: f5bigip.home.com
[+] 127.0.0.1:22 MAC Address: aa:aa:aa:aa:aa:aa
[+] 127.0.0.1:22 Management IP: 2.2.2.2
[+] 127.0.0.1:22 Product BIG-IP
[+] 127.0.0.1:22 OS Version: 15.1.0.2
[+] Config import successful
[*] Auxiliary module execution completed
```

