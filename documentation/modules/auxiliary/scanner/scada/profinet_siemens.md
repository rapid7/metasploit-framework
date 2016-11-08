Siemens Industrial controllers and most other industrial OEMs 
use a proprietary protocol to discover their devices accross a network.
In the case of Siemens this is called the Profinet Discover Protocol. 
Known in Wireshark as PN_DCP

It works purely on Layer 2 (Ethernet addresses) and sends out a single
multicast packet (making it safe to use in sensitive networks). 
Each profinet enabled responds with an array of information:
- Its IP address, Subnetmask and Gateway
- Its Profinet Devicename ('Station Name')
- The Type of station
- A Vendor ID (e.g. '002a'), signifing the vendor (e.g. 'Siemens')
- A Device Role (e.g. '01'), signifing the type of device (e.g. 'IO-Controller')
- A Device ID (e.g. '010d'), signifing the device type (e.g. 'S7-1200')

## Vulnerable Application

This is a hardware choice of design, and as such CANNOT be changed without
loss of compatibility. 
Possible mitigations include: pulling the plug (literally), using network isolation
(Firewall, Router, IDS, IPS, network segmentation, etc...) or not allowing bad
people on your network.

Most, if not all, PLC's (computers that control engines, robots, conveyor
belts, sensors, camera's, doorlocks, CRACs ...) have vulnerabilities where,
using their own tools, remote configuration and programming can be done
*WITHOUT* authentication.  Investigators and underground hackers are just now
creating simple tools to convert the, often proprietary, protocols into simple
scripts.  The operating word here is "proprietary". Right now, the only thing
stopping very bad stuff from happening. 

## Verification Steps

The following demonstrates a basic scenario, we "detect" two devices:

```
msf > search profinet
msf > use auxiliary/scanner/scada/profinet_siemens
msf auxiliary(profinet_siemens) > run

[*] Sending packet out to eth0
[+] Parsing packet from 00:0e:8c:cf:7b:1a
Type of station: ET200S CPU
Name of station: pn-io-1
Vendor and Device Type: Siemens, ET200S
Device Role: IO-Controller
IP, Subnetmask and Gateway are: 172.16.108.11, 255.255.0.0, 172.16.108.11

[+] Parsing packet from 00:50:56:b6:fe:b6
Type of station: SIMATIC-PC
Name of station: nm
Vendor and Device Type: Siemens, PC Simulator
Device Role: IO-Controller
IP, Subnetmask and Gateway are: 172.16.30.102, 255.255.0.0, 172.16.0.1

[+] I found 2 devices for you!
[*] Auxiliary module execution completed
```

## Module Options
```
msf auxiliary(profinet_siemens) > show options

Module options (auxiliary/scanner/scada/profinet_siemens):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   INTERFACE  eth0             yes       Set an interface
   TIMEOUT    2                yes       Seconds to wait, set longer on slower networks
```

By default, the module uses interface 'eth0', there is a check to see if it is live.

The module will send out an ethernet packet and wait for responses.
By default, it will wait 2 seconds for any responses, this is long enough for most networks.
Increase this on larger and/or slower networks, it just increases the wait time.
