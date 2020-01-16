# Description

This module is used to determine if the ports on target machine are closed. It sends probes containing the FIN, PSH and URG flags. Scan is faster and stealthier compared to some other scans. Following action are performed depending on the state of ports -

#### OPEN|FILTERED Port:
Detects open|filtered port via no response to the segment

#### Closed Port: 
Detects a closed port via a RST received in response to the FIN

# Required Permissions

  XMAS scan requires the use of raw sockets, and thus cannot be performed from some Windows
  systems (Windows XP SP 2, for example). On Unix and Linux, raw socket manipulations require root privileges.

## Options

  **PORTS**
  
  This is the list of TCP ports to test on each host.
  Formats like  `1-3`, `1,2,3`, `1,2-3`, etc. are all supported. Default
  options is to scan `1-10000` ports.
  
  **Timeout**

  This options states the reply read timeout in milliseconds. Default value if `500`.

  **RHOSTS**

  The target address range is defined in this option.

  **VERBOSE**
  
  Gives detailed message about the scan of all the ports. It also shows the
  ports that were not open/filtered.

# Verification Steps

  1. Do: `use auxiliary/scanner/portscan/xmas`
  2. Do: `set RHOSTS [IP]`
  3. Do: `set PORTS [PORTS]`
  4. Do: `run`
  5. The open/filtered ports will be discovered, status will be printed indicating as such.

## Scenarios
  
### Metaspliotable 2

```
msf > use auxiliary/scanner/portscan/xmas
msf auxiliary(xmas) > set rhosts 192.168.45.159
rhosts => 192.168.45.159
msf auxiliary(xmas) > set ports 1-100
ports => 1-100
msf auxiliary(xmas) > run

[*]  TCP OPEN|FILTERED 192.168.45.159:1
[*]  TCP OPEN|FILTERED 192.168.45.159:3
[*]  TCP OPEN|FILTERED 192.168.45.159:5
[*]  TCP OPEN|FILTERED 192.168.45.159:8
[*]  TCP OPEN|FILTERED 192.168.45.159:12
[*]  TCP OPEN|FILTERED 192.168.45.159:14
[*]  TCP OPEN|FILTERED 192.168.45.159:16
[*]  TCP OPEN|FILTERED 192.168.45.159:19
[*]  TCP OPEN|FILTERED 192.168.45.159:21
[*]  TCP OPEN|FILTERED 192.168.45.159:37
[*]  TCP OPEN|FILTERED 192.168.45.159:39
[*]  TCP OPEN|FILTERED 192.168.45.159:41
[*]  TCP OPEN|FILTERED 192.168.45.159:43
[*]  TCP OPEN|FILTERED 192.168.45.159:49
[*]  TCP OPEN|FILTERED 192.168.45.159:52
[*]  TCP OPEN|FILTERED 192.168.45.159:53
[*]  TCP OPEN|FILTERED 192.168.45.159:55
[*]  TCP OPEN|FILTERED 192.168.45.159:57
[*]  TCP OPEN|FILTERED 192.168.45.159:59
[*]  TCP OPEN|FILTERED 192.168.45.159:61
[*]  TCP OPEN|FILTERED 192.168.45.159:63
[*]  TCP OPEN|FILTERED 192.168.45.159:65
[*]  TCP OPEN|FILTERED 192.168.45.159:67
[*]  TCP OPEN|FILTERED 192.168.45.159:69
[*]  TCP OPEN|FILTERED 192.168.45.159:73
[*]  TCP OPEN|FILTERED 192.168.45.159:89
[*]  TCP OPEN|FILTERED 192.168.45.159:91
[*]  TCP OPEN|FILTERED 192.168.45.159:93
[*]  TCP OPEN|FILTERED 192.168.45.159:95
[*]  TCP OPEN|FILTERED 192.168.45.159:97
[*]  TCP OPEN|FILTERED 192.168.45.159:99
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
