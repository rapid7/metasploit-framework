## Vulnerable Application

This module is able to extract a zip file sent through Modbus from a pcap.

Tested with Schneider TM221CE16R

## Verification Steps

  1. Do: `use auxiliary/auxiliary/scanner/scada/modbus_zip`
  2. Do: `set PCAPFILE <PATH_TO_PCAP>` where PATH_TO_PCAP is the PATH to the pcap file
  3. Do: `exploit` extract the zip file

## Options

  **MODE**
  
  Describe what this option does / how it affects the module.

## Scenarios
 ```
msf > use auxiliary/auxiliary/scanner/scada/modbus_zip
msf auxiliary(scanner/scada/modbus_zip) > set PCAPFILE file.pcap
PCAPFILE => file.pcap
auxiliary(scanner/scada/modbus_zip) > set MODE DOWNLOAD
MODE => DOWNLOAD
msf auxiliary(scanner/scada/modbus_zip) > exploit
[*] Running module against 0.0.0.0

[*] Zip start on packet 1370
[*] Zip end on packet 1452
[*] Done!
[*] Auxiliary module execution completed
```
