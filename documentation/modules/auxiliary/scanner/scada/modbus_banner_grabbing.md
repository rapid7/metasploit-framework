## Vulnerable Application

This module will perform banner grabbing on devices that use the Modbus protocol by sending 
a payload with the function code 43 to read the target device's identification information.
For more technical information, you can refer to this link: https://en.wikipedia.org/wiki/Modbus#Available_function/command_codes.

By default the service is running on port 502, so any device with this port open could be a potential target.

## Verification Steps
  1. Do: `use auxiliary/scanner/scada/modbus_banner_grabbing`
  2. Do: `set RHOST <IP>` where IP is the IP address of the target.
  3. Do: `set UNIT_ID <ID>` where ID is a number from 0 to 254 inclusive. This is optional, the default Unit Identifier on most devices is `0`.
  4. Do: `run`

The response from the target device may contain several objects. Some of these objects can be seen below:

`vendor name, product code, min. max. revision, vendor url, product name, model name`

If the `UNIT_ID` value set by the attacker is incorrect, or if the target was unable to process the Modbus message,
a Modbus exception message will be returned from the target, which will then be output to the screen.

Successful results from the scan will be stored as a `note` in the framework. You can access these notes by typing `note` in the console.

```
msf5 auxiliary(scanner/scada/modbus_banner_grabbing) > notes

Notes
=====

 Time                     Host            Service  Port  Protocol  Type                Data
 ----                     ----            -------  ----  --------  ----                ----
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.vendorname   "Schneider Electric"
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.productcode  "BMX NOE 0100"
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.revision     "V3.10"
```

## Options
  1. `UNIT_ID` is the Unit Identifier and must be a number from 0 to 254 inclusive. By default this value is set to `0`.
  2. `RHOST` is the IP address of the target.

## Scenarios
The following scenarios describe some of the responses you may receive from the target:

### Schneider Electric BMX NOE 0100 - Successful Response

```
msf6 > use auxiliary/scanner/scada/modbus_banner_grabbing
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > set RHOSTS 192.168.1.1
RHOSTS => 192.168.1.1
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[*] 192.168.1.1:502    - Number of Objects: 3
[+] 192.168.1.1:502    - VendorName: Schneider Electric
[+] 192.168.1.1:502    - ProductCode: BMX NOE 0100
[+] 192.168.1.1:502    - Revision: V3.10
[*] 192.168.1.1:502    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Schneider Electric BMX NOE 0100 - No Reply
The target never replied to the attacker's request.

```
msf6 > use auxiliary/scanner/scada/modbus_banner_grabbing
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > set RHOSTS 192.168.1.2
RHOSTS => 192.168.1.2
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.2:502      - MODBUS - No reply
[*] 192.168.1.2:502      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Schneider Electric BMX NOE 0100 - Network Error
Some network error occurred, such as a connection error, a network timeout, or the connection was refused. Alternatively, the host may be unreachable.

```
msf6 > use auxiliary/scanner/scada/modbus_banner_grabbing
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > set RHOSTS 192.168.1.3
RHOSTS => 192.168.1.3
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.3:502     - MODBUS - Network error during payload: The connection timed out (217.71.253.52:502).
[*] 192.168.1.3:502     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Schneider Electric BMX NOE 0100 - Modbus Exception Code (i.e. Memory Parity Error)

```
msf6 > use auxiliary/scanner/scada/modbus_banner_grabbing
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > set RHOSTS 192.168.1.4
RHOSTS => 192.168.1.4
msf6 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.4:502      - Memory Parity Error: Slave detected a parity error in memory.
[*] 192.168.1.4:502      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
