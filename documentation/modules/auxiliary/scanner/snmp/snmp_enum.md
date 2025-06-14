## Description
This module performs a detailed enumeration of a host or a range through SNMP protocol. It supports hardware, software, and network information.

## Verification Steps

1. Do: ```use auxiliary/scanner/snmp/snmp_enum```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios 

```
msf > use auxiliary/scanner/snmp/snmp_enum
msf auxiliary(auxiliary/scanner/snmp/snmp_enum) > set RHOSTS 1.1.1.2
RHOSTS => 1.1.1.2
msf auxiliary(auxiliary/scanner/snmp/snmp_enum) > run

[*] System information

Hostname                : Netgear-GSM7224
Description             : GSM7224 L2 Managed Gigabit Switch
Contact                 : dookie
Location                : Basement
Uptime snmp             : 56 days, 00:36:28.00
Uptime system           : -
System date             : -

[*] Network information

IP forwarding enabled   :  no
Default TTL             :  64
TCP segments received   :  20782
TCP segments sent       :  9973
TCP segments retrans.   :  9973
Input datagrams         :  4052407
Delivered datagrams     :  1155615
Output datagrams        :  18261

[*] Network interfaces

Interface [ up ] Unit: 1 Slot: 0 Port: 1 Gigabit - Level

	Id              : 1
	Mac address     : 00:0f:b5:fc:bd:24
	Type            : ethernet-csmacd
	Speed           : 1000 Mbps
	Mtu             : 1500
	In octets       : 3716564861
	Out octets      : 675201778
...snip...
[*] Routing information

     Destination         Next hop             Mask           Metric

         0.0.0.0      5.1.168.192          0.0.0.0                1
       1.0.0.127        1.0.0.127  255.255.255.255                0

[*] TCP connections and listening ports

   Local address       Local port   Remote address      Remote port            State

         0.0.0.0               23          0.0.0.0                0           listen
         0.0.0.0               80          0.0.0.0                0           listen
         0.0.0.0             4242          0.0.0.0                0           listen
       1.0.0.127             2222          0.0.0.0                0           listen

[*] Listening UDP ports

   Local address       Local port

         0.0.0.0                0
         0.0.0.0              161
         0.0.0.0              514

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(auxiliary/scanner/snmp/snmp_enum) >
```
