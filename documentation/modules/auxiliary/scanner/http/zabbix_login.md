## Vulnerable Application

This module attempts to login to zabbix server, by default module will use default credentials and also supports user defined login credentials
### Environment

Zabbix team provides virtual images of multiple versions of Zabbix server.
In this example versions 3, 4 and 5(latest) were tested.

## Verification Steps

  1. Install zabbix 
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/zabbix_login```
  4. Do: ```set rhosts [ip]```
  5. Do: ```run```
  6. If no credentials supplied, module will try zabbix default credentails and if successful the following line is 
     displayed:
        [+] 192.168.0.151 - Success: 'Admin:zabbix'

## Options

  **TARGETURI**

  Folder where login page is located.  Versions 3 and 4 by default use /zabbix/.
  This module sets **TARGETURI** to /zabbix/ by default.

  Note that version 5 of zabbix, location of login page has moved to /.  If module is used against zabbix version 5, 
  **TARGETURI** needs to be changed to /.  To do that run following in metasploit
  ````set TARGETURI / ````

## Scenarios

### Example run against zabbix version 3

```
msf5 > use auxiliary/scanner/http/zabbix_login
msf5 auxiliary(scanner/http/zabbix_login) > set RHOSTS 192.168.0.151
RHOSTS => 192.168.0.151
msf5 auxiliary(scanner/http/zabbix_login) > run

[*] 192.168.0.151:80 - Found Zabbix version
[*] 192.168.0.151:80 - Zabbix has disabled Guest mode
[+] 192.168.0.151:80 - Success: 'Admin:zabbix'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/zabbix_login) > 

```
