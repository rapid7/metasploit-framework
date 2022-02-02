## Vulnerable Application

  The Moxa protocol listens on 4800/UDP and will respond to broadcast
  or direct traffic.  The service is known to be used on Moxa devices
  in the NPort, OnCell, and MGate product lines.

  A discovery packet compels a Moxa device to respond to the sender
  with some basic device information that is needed for more advanced
  functions.  The discovery data is 8 bytes in length and is the most
  basic example of the Moxa protocol.  It may be sent out as a
  broadcast (destination 255.255.255.255) or to an individual device.

  Devices that respond to this query may be vulnerable to serious
  information disclosure vulnerabilities, such as CVE-2016-9361.

  The module is the work of Patrick DeSantis of Cisco Talos and is
  derived from original work by K. Reid Wightman. Tested and validated
  on a Moxa NPort 6250 with firmware versions 1.13 and 1.15.

  The discovery request contains the bytes:
  
  `\x01\x00\x00\x08\x00\x00\x00\x00`

  Where the function code (first byte) 0x01 is Moxa discovery/identify
  and the fourth byte is the length of the full data payload.

  The first byte of a response will always be the func code + 0x80
  (the most significant bit of the byte is set to 1, so 0b00000001
  becomes 0b10000001, or 0x81).

  A valid response is 24 bytes, starts with 0x81, and contains the values
  0x00, 0x90, 0xe8 (the Moxa OIU) in bytes 14, 15, and 16.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/scanner/scada/moxa_discover```
  3. Do: ```set RHOSTS```
  4. Do: ```run```
  4. Devices running the Moxa service should respond

## Options

  **RHOSTS**

  Target(s) to scan; can be single target, a range, or broadcast.

## Scenarios

  ```
  msf > hosts

  Hosts
  =====

  msf > use auxiliary/scanner/scada/moxa_discover
  msf auxiliary(moxa_discover) > set RHOSTS 192.168.127.254
  RHOSTS => 192.168.127.254
  msf auxiliary(moxa_discover) > show options

  Module options (auxiliary/scanner/scada/moxa_discover):

    Name       Current Setting  Required  Description
    ----       ---------------  --------  -----------
    BATCHSIZE  256              yes       The number of hosts to probe in each set
    RHOSTS     192.168.127.254  yes       The target address range or CIDR identifier
    RPORT      4800             yes       The target port (UDP)
    THREADS    10               yes       The number of concurrent threads

  msf auxiliary(moxa_discover) > run

  [+] 192.168.127.254:4800 Moxa Device Found!
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf auxiliary(moxa_discover) > hosts

  Hosts
  =====

  address          mac  name  os_name  os_flavor  os_sp  purpose  info         comments
  -------          ---  ----  -------  ---------  -----  -------  ----         --------
  192.168.127.254             Unknown                    device   Moxa Device

  msf auxiliary(moxa_discover) >
  ```
