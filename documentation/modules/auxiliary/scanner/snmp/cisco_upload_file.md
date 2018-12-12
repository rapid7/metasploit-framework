## Vulnerable Application

  Cisco IOS devices can be configured to retrieve, via tftp,  a file via SNMP.
  This is a well [documented](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15217-copy-configs-snmp.html#copying_startup)
  feature of IOS and many other networking devices, and is part of an administrator functionality.
  A read-write community string is required, as well as a tftp server (metasploit includes one).
  The file will be saved to `flash:`.

## Verification Steps

  1. Enable SNMP with a read/write community string on IOS: `snmp-server community private rw`
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/snmp/cisco_upload_file```
  4. Do: ```set COMMUNITY [read-write snmp]```
  5. Do: ```set rhosts [ip]```
  6. Do: ```set source [file]```
  7. Do: ```run```

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
