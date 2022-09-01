## Vulnerable Application

  [Web Services Dynamic Discovery (WS-Discovery)](https://en.wikipedia.org/wiki/WS-Discovery) is a multicast discovery protocol utilising SOAP over UDP to locate web services on a local network.

  Web service enabled devices typically include printers, scanners and file shares.

  The reply from some devices may include optional vendor extensions. This data may include network information such as the device MAC address and hostname, or hardware information such as the serial number, make, and model.


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/scanner/wsdd/wsdd_query`
  3. Do: `set RHOSTS [IP]` (Default: `239.255.255.250`)
  4. Do: `run`


## Scenarios

  ```
  msf > use auxiliary/scanner/wsdd/wsdd_query 
  msf auxiliary(wsdd_query) > set rhosts 239.255.255.250
  rhosts => 239.255.255.250
  msf auxiliary(wsdd_query) > run

  [*] Sending WS-Discovery probe to 1 hosts
  [+] 10.1.1.184 responded with:
  Address: http://10.1.1.184:3911/ 
  Types: wsdp:Device, wprt:PrintDeviceType, wscn:ScanDeviceType, hpd:hpDevice
  Vendor Extensions: {"HardwareAddress"=>"123456789ABC", "UUID"=>"12345678-1234-1234-abcd-123456789abc", "IPv4Address"=>"10.1.1.123", "Hostname"=>"HP09AAFB", "DeviceId"=>"MFG:HP;MDL:Photosmart 5520 series;DES:CX042A;", "DeviceIdentification"=>{"MakeAndModel"=>"Photosmart 5520 series", "MakeAndModelBase"=>"Photosmart 5520 series"}, "SerialNumber"=>"123456", "Services"=>" Print9100 SclScan RESTScan CIFS DOT4 LEDM", "AdapterType"=>"WifiEmbedded"}
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

