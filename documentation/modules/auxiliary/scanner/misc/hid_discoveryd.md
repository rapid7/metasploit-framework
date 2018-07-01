## Description

  Discover information from the `discoveryd` service
  exposed by HID VertX and Edge door controllers.


## Verification Steps

  To test this module, ensure there is at least one
  HID `discoveryd` service on the same network.

  1. Start `msfconsole`
  2. `use auxiliary/scanner/misc/hid_discoveryd`
  3. `set RHOSTS [IP]` (Default: `255.255.255.255`)
  4. `run`
  5. You should be notified of any `discoveryd` services on the local network


## Scenarios

  ```
  msf5 > use auxiliary/scanner/misc/hid_discoveryd 
  msf5 auxiliary(scanner/misc/hid_discoveryd) > set rhosts 10.123.123.123
  rhosts => 10.123.123.123
  msf5 auxiliary(scanner/misc/hid_discoveryd) > run

  [*] Sending HID discover probe to 1 hosts
  [*] 10.123.123.123:4070 - Sending HID discover probe
  [+] 10.123.123.123 responded with:
  Name: NoEntry
  Model: EH400
  Version: 2.3.1.603 (04/23/2012)
  MAC Address: 00:06:8E:FF:FF:FF
  IP Address: 10.123.123.123
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

