## Description
This module will simply scan a range of hosts and queries via SNMP to determine any available shares.

## Verification Steps

1. Do: ```use auxiliary/scanner/snmp/snmp_enumshares```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/snmp/snmp_enumshares
msf auxiliary(scanner/snmp/snmp_enumshares) > set RHOSTS 1.1.1.200-211
RHOSTS => 1.1.1.200-211
msf auxiliary(scanner/snmp/snmp_enumshares) > set THREADS 11
THREADS => 11
msf auxiliary(scanner/snmp/snmp_enumshares) > run 

[+] 1.1.1.201 
	shared_docs -  (C:\Documents and Settings\Administrator\Desktop\shared_docs)
[*] Scanned 02 of 11 hosts (018% complete)
[*] Scanned 03 of 11 hosts (027% complete)
[*] Scanned 05 of 11 hosts (045% complete)
[*] Scanned 07 of 11 hosts (063% complete)
[*] Scanned 09 of 11 hosts (081% complete)
[*] Scanned 11 of 11 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/snmp/snmp_enumshares) > 
```

