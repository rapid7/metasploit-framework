## Vulnerable Application
BACnet is a Data Communication Protocol for Building Automation and Control Networks.
Developed under the auspices of the American Society of Heating,
 Refrigerating and Air-Conditioning Engineers (ASHRAE), BACnet is an American national standard,
 a European standard, a national standard in more than 30 countries, and an ISO global standard.
 The protocol is supported and maintained by ASHRAE Standing Standard Project Committee 135

This script polls bacnet devices with a l3 broadcast Who-is message
and for each reply communicates further to discover more data and saves the data into metasploit.
Each bacnet device responds with this data:
- It's IP address, and BACnet/IP address (if the device is nested).
- It's device number.
- Model name.
- Application software version.
- Firmware revision.
- Device description.
## Verification Steps

  1. Start msfconsole.
  2. Do: `use auxiliary/scanner/scada/bacnet_l3`.
  3. Do: `set INTERFACE`.
  5. Do: `run`.
  6. Devices running the BACnet protocol should respond with data.

## Options
A user can choose between the interfaces of his host (e.g. eth1, ens192...),
the number of Who-is packets to send - for reliability purposes, the time (in seconds) to wait for packets to arrive
and the UDP port, the default is 47808.

The user can always check these options via the `show options` command.

```
msf auxiliary(profinet_siemens) > show options

Module options (auxiliary/scanner/scada/bacnet_l3):

Name       Current Setting  Required  Description
----       ---------------  --------  -----------
COUNT      1                yes       The number of times to send each packet
INTERFACE  eth1             yes       The interface to scan from
PORT       47808            yes       BACnet/IP UDP port to scan (usually between 47808-47817)
TIMEOUT    1                yes       The socket connect timeout in seconds
```

## Scenarios

The following demonstrates a basic scenario, we "detect" two devices:

```

msf > use auxiliary/scanner/scada/bacnet_l3
msf auxiliary(auxiliary/scanner/scada/bacnet_l3) > run

[*] Broadcasting Who-is via eth1
[*] found 2 devices
[*] Querying device number 826001 in ip 192.168.13.11
[*] Querying device number 4194303 in ip 192.168.13.12
[*] Done scanning
[+] for asset number 826001:
        model name: iSMA-B-4U4A-H-IP
        firmware revision: 6.2
        application software version: GC5 6.2
        description: BACnet iSMA-B-4U4A-H-IP Module

[+] for asset number 4194303:
        model name: PXG3.L-1
        firmware revision: FW=01.21.30.38;WPC=1.4.131;SVS-300:SBC=13.21;
        application software version:
        description: BacnetRouter

[+] Successfully saved data to local store named bacnet-discovery.xml
[*] Done.
[*] Auxiliary module execution completed
```
