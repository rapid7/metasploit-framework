## Vulnerable Application

This module will check the file system and registry for particular artifacts.

The list of artifacts is read in YAML format from `data/post/enum_artifacts_list.txt`
or a user specified file. Any matches are written to the loot.


## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/windows/gather/enum_artifcats`
1. Do: `set SESSION <session id>`
1. Do: `run`

## Options

### ARTIFACTS

Full path to artifacts file.

## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1)

```
msf6 > use post/windows/gather/enum_artifacts 
msf6 post(windows/gather/enum_artifacts) > set session 1
session => 1
msf6 post(windows/gather/enum_artifacts) > set verbose true
verbose => true
msf6 post(windows/gather/enum_artifacts) > run

[*] Searching for artifacts of test_evidence
[*] Processing 2 file entries for test_evidence ...
[*] Processing 2 registry entries for test_evidence ...
[*] Artifacts of test_evidence found.
Evidence of test_evidence found.
	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI\DisplayName

[+] Enumerated Artifacts stored in: /root/.msf4/loot/20220807015628_default_192.168.200.190_enumerated.artif_933981.txt
[*] Post module execution completed
```
