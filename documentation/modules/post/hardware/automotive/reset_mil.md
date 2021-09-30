## Introduction

This module clears Diagnostic Trouble Codes and resets the mileage.

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
CAN ID to clear DTCs and reset MIL (Default: 0x7DF)

**CANBUS**
CAN Bus to perform scan on, defaults to connected bus

## Scenarios
Using UDS simulator for testing the clearing of DTCs and resetting MIL:

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

hwbridge > run post/hardware/automotive/reset_mil CANBUS=vcan0

[*] Clearing DTCs and resetting MIL......

```

You can use candump to verify the CAN messages being sent:

```
└─$ candump vcan0        
  vcan0  7F1   [8]  03 22 F1 90 00 00 00 00
```

UDS Server Output
```
└─$ ./uds-server -v -V "PWN3D" vcan0
Using CAN interface vcan0
Fuzz level set to: 0
Pkt: 7DF#01 04 55 55 55 55 55 55
Unhandled mode/sid: Clear DTCs
Pkt: 7DF#02 11 01 00 00 00 00 00
```
