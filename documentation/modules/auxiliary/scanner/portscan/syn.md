## Description
  
This module will attempt to initiate a three-way handshake with every 
on the victim machine. It is done by sending a SYN packet and if victim replies with a SYN/ACK packet that means the port is open. Then the attacker sends a RST packet as a result 

## Vulnerable Application

  Any reachable TCP endpoint is a potential target.

## Options

  **PORTS**
  
  This is the list of ports to test for TCP Scan on each host.
  Formats like  `1-3`, `1,2,3`, `1,2-3`, etc. are all supported.Default
  options is to scan `1-10000` ports.

  **TIMEOUT**
  
   Maximum time (seconds) to wait for a response. The default value is 500.
 
  **ConnectTimeout**
  
  This options states the maximum number of seconds to establish a tcp 
  connection. Default value if 10.
 
  **VERBOSE**
  
  Gives detailed message about the scan of all the ports. It also shows the
  ports that were closed.

## Verification Steps

  1. Do: `use auxiliary/scanner/portscan/tcp`
  2. Do: `set RHOSTS [IP]`
  3. Do: `set RPORT [PORTS]`
  4. Do: `run`
  5. If any of the TCP ports were open they will be discovered, status will be printed indicated as such.

## Scenarios
  
### Metaspliotable 2

```
msf > use auxiliary/scanner/portscan/syn
msf auxiliary(syn) > set RHOSTS 192.168.45.159
RHOSTS => 192.168.45.159
msf auxiliary(syn) > set PORTS 1-10000
PORTS => 1-10000
msf auxiliary(syn) > run
[*]  TCP OPEN 192.168.45.159:22
[*]  TCP OPEN 192.168.45.159:23
[*]  TCP OPEN 192.168.45.159:111
[*]  TCP OPEN 192.168.45.159:445
[*]  TCP OPEN 192.168.45.159:512
[*]  TCP OPEN 192.168.45.159:513
[*]  TCP OPEN 192.168.45.159:1099
[*]  TCP OPEN 192.168.45.159:2121
[*]  TCP OPEN 192.168.45.159:3306
[*]  TCP OPEN 192.168.45.159:3632
[*]  TCP OPEN 192.168.45.159:6000
[*]  TCP OPEN 192.168.45.159:6697
[*]  TCP OPEN 192.168.45.159:8009
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
