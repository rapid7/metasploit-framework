## Overview

This module connects to any Hardware device that supports the HWBridge API.  For details
on the HWBridge API see [API Reference](http://opengarages.org/hwbridge).  On successful connection to a HWBridge a
HWBridge session will be established.

## Devices

When run on linux you can use the auxiliary/server/local_hwbridge to talk to any device supported by SocketCAN.
It will work with natively supported devices (can), serial devices (slcan) and even virtual devices (vcan). For
a list of supported SocketCAN hardware see the [eLinux website](http://elinux.org/CAN_Bus).

Any ELM327 or STN1100 interface will work with the HWBridge. If you pick up any device that uses either of
these chipsets can can connect via serial (USB or Bluetooth) it will work.  These are popular and inexpensive
devices.  They are not as fast as some of the native CAN devices but they are plentiful and cheap.

This module was also tested with the [Particle](https://Particle.io) Photon board.  To utilize a Particle.io Photon board you
will want to add the spark-msf-relay library to your project.  See the library examples for details on
how to extend your project to integrate it with Metasploit.  If you are building an automotive project
and you are using the [Carloop](https://carloop.io) then the spark-msf-relay library also includes an example app for carloop
that you can simply flash to the device for full support.

2. Generic ELM327: [ebay](http://www.ebay.com/itm/like/221821719820)

## Bluetooth Adapter Connection

Bluetooth HWBridge adapters, depending on the Operating System, may take several additional steps to establish a connection and communications bus.
The following steps were [recorded during the testing of this module](https://github.com/rapid7/metasploit-framework/pull/7795#issuecomment-274302326)
on setting up the [BAFX 34t5](https://bafxpro.com/products/obdreader) with Kali Linux 2016.2 (rolling).

1. Most Bluetooth HWBridge adapters, speak serial. So you will need to get the ruby gem "serialport": ```gem install serialport```
2. Ensure no locks on the Bluetooth device via: `rfkill list` (and subsequent `unblock` commands)
3. Make sure Bluetooth service is started: `/etc/init.d/bluetooth start`, or `bluetoothd`
4. Start bluetoothctl: `bluetoothctl`
5. Turn on scanning: `scan on`
6. Turn on agent: `agent on`
7. Make sure we can see OBDII: `devices`
8. Attempt to pair: `[bluetooth]# pair 00:0D:18:AA:AA:AA`

  ```
  Attempting to pair with 00:0D:18:AA:AA:AA
  [CHG] Device 00:0D:18:AA:AA:AA Connected: yes
  ```
9. If prompted for pin: `1234`
10. Trust the device in order to not put in the pin again: `trust 00:0D:18:AA:AA:AA`
11. Use rfcomm to make the connection and serial interface in a different window (not bluetoothctl): `rfcomm connect /dev/rfcomm1 "00:0D:18:AA:AA:AA"`

## Options

 **TARGETURI**

 Specifies the base target URI to communicate to the HWBridge API.  By default this is '/' but it
 could be things such as '/api' or the randomly generated URI from the local_hwbridge module

 **DEBUGJSON**

 Prints out all the JSON packets that come from the HWBridge API.  Useful for troubleshooting
 a device.

 This module also supports all the other HTTP Client options typical to Metaplsoit.

## Sample Connection

For an example, lets say we connect to a HW Bridge that is designed for automotive use
and has support for multiple CAN buses.  The remote device in our example is called 'carhax'

```
msf > use auxiliary/client/hwbridge/connect 
msf auxiliary(connect) > set rhost carhax
rhost => carhax
msf auxiliary(connect) > run

[*] Attempting to connect to carhax...
[*] Hardware bridge interface session 1 opened (127.0.0.1 -> 127.0.0.1) at 2016-12-29 13:49:55 -0800
[+] HWBridge session established
[*] HW Specialty: {"automotive"=>true}  Capabilities: {"can"=>true, "custom_methods"=>true}
[!] NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge
[!]          could have real world consequences.  Use this module in a controlled testing
[!]          environment and with equipment you are authorized to perform testing on.
[*] Auxiliary module execution completed
```

On successful connection to a Hardware device you will be prompted with a special notice to
remind you that any action you take on the HWBridge could have physical affects and consequences.
Our lawyers asked us to put that there.  You can verify the session was created by type 'sessions'

```
msf auxiliary(connect) > sessions

Active sessions
===============

  Id  Type                   Information  Connection
  --  ----                   -----------  ----------
  1   hwbridge cmd/hardware  automotive   127.0.0.1 -> 127.0.0.1 (10.1.10.21)

```
## Automotive Extension

If a device specifies a hw_specialty then it can load custom extensions.  For instance, if
a defice defines its specialty is automotive then Metasploit will load a custom automotive
extension that gives you a few generic commands you can use on autotive systems such as the
ability to send arbitrary CAN packets down the bus.  It also allows you to run any
post/hardware/automotive modules.

For instance you can run post/hardware/automtive/getvinfo to retrieve vehicle information
via UDS Mode $9 commands.

```
hwbridge > run post/hardware/automotive/getvinfo CANBUS=can2

[*] Supported PIDS: [2, 4, 6, 8]
[*] VIN: 1G1ZT53826F109149
[*] Calibration ID: x
[*] PID 6 Response: ["00", "00", "C4", "E9", "00", "00", "17", "33", "00", "00", "00", "00"]
[*] PID 8 Response: ["00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"]
```
run 'supported_buses' for a list of available buses provided by your hardware.  And as always you can
type 'help' for a list of available commands and each command should support '-h' to additional
argument help.

## Custom Method Extension

It is possible for the hardware device to report functionality that Metasploit has no knowledge
of.  For instance, perhaps the device has a unique capability that isn't standard or can be done
100% in hardware.  In order to utilize that functionality the HW device can report that it has
custom_methods as a capability.  At which point Metasploit will then query the custom methods
and their argument syntax.  These methods will become available as command line options
within the hardware bridge.

For a simple example of a custom method see auxiliary/server/local_hwbridge for a more complete
list on how to define custom methods see the [API Reference](http://opengarages.org/hwbridge).
