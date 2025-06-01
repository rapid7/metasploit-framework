## Description

Detect common UDP services using sequential probes.

## Verification Steps

1. Do: `use auxiliary/scanner/discovery/udp_probe`
2. Do: `set RHOSTS [IP]`
5. Do: `set THREADS [number of threads]`
6. Do: `run`

## Scenarios

```
msf6 auxiliary(scanner/discovery/udp_probe) > use modules/auxiliary/scanner/discovery/udp_probe
msf6 auxiliary(scanner/discovery/udp_probe) > set RHOSTS 10.0.3.5
RHOSTS => 10.0.3.5
msf6 auxiliary(scanner/discovery/udp_probe) > run
[+] Discovered SNMP on 10.0.3.5:161 (Hardware: Intel64 Family 6 Model 142 Stepping 12 AT/AT COMPATIBLE - Software: Windows Version 6.1 (Build 7601 Multiprocessor Free))
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
