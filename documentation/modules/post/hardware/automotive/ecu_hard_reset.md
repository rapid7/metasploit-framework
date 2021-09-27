## Introduction

This module performs hard reset in the ECU Reset Service Identifier (0x11).

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

**ARBID**
CAN ID to perform ECU Hard Reset (Default: 0x7DF)

**CANBUS**
CAN Bus to perform scan on, defaults to connected bus

## Scenarios
Using UDS simulator for testing ECU hard reset:

```
msf5 auxiliary(client/hwbridge/connect) > run
[*] Running module against 127.0.0.1

[*] Attempting to connect to 127.0.0.1...
[*] Hardware bridge interface session 2 opened (127.0.0.1 -> 127.0.0.1) at 2019-09-11 04:59:40 -0700
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

hwbridge > run post/hardware/automotive/ecu_hard_reset CANBUS=vcan0

[*] Performing ECU Hard Reset...

```

You can use candump to verify the CAN messages being sent:

```
─$ candump vcan0          
  vcan0  7DF   [8]  02 11 01 00 00 00 00 00
```

UDS Server Output
```
└─$ ./uds-server -v -V "PWN3D" vcan0            
Using CAN interface vcan0
Fuzz level set to: 0
Pkt: 7DF#02 11 01 00 00 00 00 00 
Unhandled mode/sid: ECU Reset
```
