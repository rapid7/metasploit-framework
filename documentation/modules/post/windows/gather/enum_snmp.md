## Vulnerable Application

This module will enumerate the SNMP service configuration.

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/enum_snmp`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

## Scenarios

### Windows Server 2008 (x64)

```
msf6 > use post/windows/gather/enum_snmp
msf6 post(windows/gather/enum_snmp) > set session 1
session => 1
msf6 post(windows/gather/enum_snmp) > run

[*] Running module against WIN-17B09RRRJTG (192.168.200.218)
[*] Checking if SNMP service is installed
[*] 	SNMP is installed!
[*] Enumerating community strings
[*] 
[*] 	Community Strings
[*] 	=================
[*] 	
[*] 	 Name    Type
[*] 	 ----    ----
[*] 	 secret  READ & WRITE
[*] 	 test    READ ONLY
[*] 
[*] Enumerating Permitted Managers for Community Strings
[*] 	SNMP packets are accepted from any host
[*] Enumerating Trap configuration
[*] Community Name: test
[*] 	Destination: 127.0.0.1
[*] 	Destination: snmp.local
[*] Post module execution completed
```
