## Description
This module queries a range of hosts via SNMP and gathers a list of usernames on the remote system.

## Verification Steps

1. Do: ```use auxiliary/scanner/snmp/snmp_enumusers```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [NUMBER OF THREADS]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/snmp/snmp_enumusers
msf auxiliary(scanner/snmp/snmp_enumusers) > set RHOSTS 1.1.1.200-211
RHOSTS => 1.1.1.200-211
msf auxiliary(scanner/snmp/snmp_enumusers) > set THREADS 11
THREADS => 11
msf auxiliary(scanner/snmp/snmp_enumusers) > run 

[+] 1.1.1.201 Found Users: ASPNET, Administrator, Guest, HelpAssistant, SUPPORT_388945a0, victim 
[*] Scanned 02 of 12 hosts (016% complete)
[*] Scanned 05 of 12 hosts (041% complete)
[*] Scanned 06 of 12 hosts (050% complete)
[*] Scanned 07 of 12 hosts (058% complete)
[*] Scanned 08 of 12 hosts (066% complete)
[*] Scanned 09 of 12 hosts (075% complete)
[*] Scanned 11 of 12 hosts (091% complete)
[*] Scanned 12 of 12 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/snmp/snmp_enumusers) >
```

