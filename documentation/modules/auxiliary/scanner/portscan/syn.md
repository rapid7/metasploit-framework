## Description
  
This module will attempt to initiate a TCP/IP connection with ports on the victim machine. It is this done by sending a SYN packet, and if victim replies with a SYN/ACK packet 
that means the port is open. Then the attacker sends a RST packet, and as a result the victim's machine assumes that there is a communication error. 
The attacker now knows the state of port without a full tcp connection. Major benefit of TCP SYN scan is that most logging applications do not log the TCP/RST by default.

## Options

  **PORTS**
  
  This is the list of TCP ports to test on each host.
  Formats like  `1-3`, `1,2,3`, `1,2-3`, etc. are all supported. Default
  options is to scan `1-10000` ports.

  **TIMEOUT**
  
   Maximum time to wait for a response. The default value is 500 milliseconds.
  
  **VERBOSE**
  
  Gives detailed message about the scan of all the ports. It also shows the
  ports that were closed.

## Verification Steps

  1. Do: `use auxiliary/scanner/portscan/syn`
  2. Do: `set RHOSTS [IP]`
  3. Do: `set PORTS [PORTS]`
  4. Do: `run`
  5. If any of the TCP ports were open they will be discovered, status will be printed indicating as such.

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
