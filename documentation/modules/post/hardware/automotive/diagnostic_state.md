## Introduction
This module will keep the vehicle in a diagnostic state on rounds by sending tester present packet.

## Verification Steps

Fire up virtual CAN bus:

1. `sudo modprobe can`
2. `sudo modprobe vcan`
3. `sudo ip link add dev vcan0 type vcan`
4. `sudo ip link set up vcan0`

Launch msf:

5. Start `msfconsole`
6. `use auxiliary/server/local_hwbridge`
7. `set uripath testbus`
8. `run`
9. `use auxiliary/client/hwbridge/connect`
10. `set targeturi testbus`

## Options

```
Module options (post/hardware/automotive/diagnostic_state):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ARBID    0x7DF            no        CAN ID to perform Diagnostic State
   CANBUS                    no        CAN Bus to perform scan on, defaults to connected bus
   ROUNDS   500              yes       Number of executed rounds
   SESSION                   yes       The session to run this module on.
```

## Scenarios
You can test this module doing a candump and you should receive a response for each can frame in a loop at 0x7E8 when running UDS Simulator.

```
msf5 auxiliary(client/hwbridge/connect) > run
[*] Running module against 127.0.0.1

[*] Attempting to connect to 127.0.0.1...
[*] Hardware bridge interface session 1 opened (127.0.0.1 -> 127.0.0.1) at 2019-09-11 04:59:40 -0700
[+] HWBridge session established
[*] HW Specialty: {"automotive"=>true}  Capabilities: {"can"=>true, "custom_methods"=>true}
[!] NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge
[!]          could have real world consequences.  Use this module in a controlled testing
[!]          environment and with equipment you are authorized to perform testing on.
[*] Auxiliary module execution completed
msf5 auxiliary(client/hwbridge/connect) > sessions

Active sessions
===============

  Id  Name  Type                   Information  Connection
  --  ----  ----                   -----------  ----------
  1         hwbridge cmd/hardware  automotive   127.0.0.1 -> 127.0.0.1 (127.0.0.1)

msf5 auxiliary(client/hwbridge/connect) > sessions -i 1
[*] Starting interaction with 1...

hwbridge > run post/hardware/automotive/diagnostic_state canbus=vcan0

[*] Putting the vehicle in a diagnostic state...
[*] In order to keep the vehicle in this state, you need to continuously send a packet to let the vehicle know that a diagnostic technician is present.
hwbridge > 
```

You can use candump to verify the CAN messages being sent:

```
─$ candump vcan0          
└─$ candump vcan0
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E
  vcan0  7E8   [4]  03 7E 00 00
  vcan0  7DF   [2]  01 3E

-- snippet --
```

UDS Server Output
```
└─$ ./uds-server -v -V "PWN3D" vcan0
Using CAN interface vcan0
Fuzz level set to: 0
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 
Pkt: 7DF#01 3E 

-- snippet --
```
