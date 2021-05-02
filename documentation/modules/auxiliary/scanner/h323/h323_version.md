## Introduction

This module scans for h.323 servers and determines the version and information about the server. 

## Usage

```
msf5 auxiliary(scanner/sip/options) > use auxiliary/scanner/h323/h323_version 
msf5 auxiliary(scanner/h323/h323_version) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf5 auxiliary(scanner/h323/h323_version) > run

[+] 1.1.1.1:1720    - 1.1.1.1:1720 Protocol: 3  VendorID: 0x6100023c  VersionID: v.5.4  ProductID: Gateway  
[*] 1.1.1.1:1720    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
