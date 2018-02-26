## Overview

This is a sample hardware bridge that demonstrates how to connect the HWBridge API to metasploit.
It demonstrates some bare minimum capabilities to report back to the hardware connector and
establish a hwbridge session.  This module provides an example on how to connect any hardware
component to Metasploit.  It is also a fully functional interface to SocketCAN and will work
to create an automotive HW Bridge.

## Setup a Test

To experimient with using Metasploit to send automtovie CAN bus packets you can use
the SocketCAN capabilities of Linux to create a virtual CAN device.  NOTE: If you have a
supported CAN sniffer you could also use a real can device.

In order for the local_hwbridge to inteface with SocketCAN you will need:

* can-utils

Once those are installed you can setup a virtual CAN inteface using:

```
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Once that is setup you can simply launch the module and it should auto detect any
CAN intefaces you have active on the system.

```
msf > use auxiliary/server/local_hwbridge 
msf auxiliary(local_hwbridge) > run
[*] Auxiliary module execution completed

[*] Using URL: http://0.0.0.0:8080/xaUKu68Va
[*] Local IP: http://10.1.10.21:8080/xaUKu68Va
[*] Server started.
```
By default it will create a random URI, in this case it's xaUKu68Va.

## Connecting to the HWBridge

You will need to use the auxiliary/client/hwbridge/connect to connect
to the local_hwbridge.  You can either use the same machine or another machine to
connect to your local_hwbridge.  Just make sure the TARGETURI matches the randomly
generated URI

```
set TARGETURI xaUKu68Va
```
Then simply type run and you should connect to the HW bridge and a hwbridge session
should be established.  You can switch to the hwbridge session to interact with
this module.

See the documentation for auxiliary/client/hwbridge/connect for more information on
the hwbridge sessions.

