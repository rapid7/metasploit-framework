## Vulnerable Application

This module will perform Banner grabbing in devices that uses the Modbus protocol.
The module will send a payload with the function code 43 which is used to read device identification.
For more technical information, you can refer to this link: https://en.wikipedia.org/wiki/Modbus#Available_function/command_codes.

Any device with the 502 port exposed could be a potential target.
A search in Shodan with the Dork `port:502` it's an easier way to find targets.
Also you can filter the results by 'product'.

## Verification Steps
  1. Do: ```use auxiliary/scanner/scada/modbus_banner_grabbing```
<<<<<<< HEAD
  2. Do: ```set RHOST <IP>```
  3. Do: ```set UNIT_ID <ID>```
=======
  2. Do: ```set RHOST <IP>``` where IP is the IP address of the target.
  3. Do: ```set UNIT_ID <ID>``` where ID is a number between 1 and 254. This is optional, default Unite Identifier is set to ```0```.
>>>>>>> Update documentation/modules/auxiliary/scanner/scada/modbus_banner_grabbing.md
  4. Do: ```run```

You can expect receive as response which may contain some of the following objects:

```vendor name, product code, min. max. revision, vendor url, product name, model name, etc.```

If the ```UNIT_ID``` value is not the correct one or the response contains an error you will receive one Modbus exception code message.

Successful results from the scan will be stored as a ```note``` in the project. You can access by typing ```note``` in the console.

```msf5 
auxiliary(scanner/scada/modbus_banner_grabbing) > notes

Notes
=====

 Time                     Host            Service  Port  Protocol  Type                Data
 ----                     ----            -------  ----  --------  ----                ----
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.vendorname   "Schneider Electric"
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.productcode  "BMX NOE 0100"
 2020-07-06 13:25:50 UTC  192.168.1.1     modbus   502   tcp       modbus.revision     "V3.10"
 ```

## Options
  1. ```UNIT_ID``` is the Unite Identifier and must be a number between 1 and 254. By default is set to ```0```.
  2. ```RHOST``` is the IP address of the target.

## Scenarios
Here are some of the possible responses that you may receive from the target.

### Execution Successfull

Target responds with some object information like ```Vendor Name```, ```Product Code``` and ```Revision```.

```msf5 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[*] 192.168.1.1:502    - Number of Objects: 3
[+] 192.168.1.1:502    - VendorName: Schneider Electric
[+] 192.168.1.1:502    - ProductCode: BMX NOE 0100
[+] 192.168.1.1:502    - Revision: V3.10
[*] 192.168.1.1:502    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Not Reply
The target never reply the request.

```msf5 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.2:502      - MODBUS - No reply
[*] 192.168.1.2:502      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Network Error

Connection errors, network timeout, host unreachable or connection refused.

```msf5 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.3:502     - MODBUS - Network error during payload: The connection timed out (217.71.253.52:502).
[*] 192.168.1.3:502     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Modbuss exception codes (I.e. Memory Parity Error)

```msf5 auxiliary(scanner/scada/modbus_banner_grabbing) > run

[-] 192.168.1.4:502      - Memory Parity Error: Slave detected a parity error in memory.
[*] 192.168.1.4:502      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
