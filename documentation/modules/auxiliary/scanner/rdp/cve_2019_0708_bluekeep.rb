[CVE-2019-0708](https://nvd.nist.gov/vuln/detail/CVE-2019-0708) ("BlueKeep")  may allow an unauthenticated attacker to gain remote code execution on an unpatched Microsoft Windows workstation or server exposing the [Remote Desktop Protocol (RDP)](https://docs.microsoft.com/en-us/windows/desktop/termserv/remote-desktop-protocol).  As a result, the vulnerability has the maximum CVSS score of 10.0.

The vulnerability exists and been patched in workstation editions of Windows XP, Windows Vista, and Windows 7.  Server releases of Windows are also affected and have been patched: Windows 2003, Windows 2008 and Windows 2008 R2.

This module, `auxiliary/scanner/rdp/cve_2019_0708_bluekeep`, scans all versions of Windows, reporting back the vulnerable state of one or more targets.  The vulnerability is not known to exist in versions of Windows 8 (or above) or Windows 2012 (or above).  However, the scanner can safely be used against all Windows versions without effect on the RDP service or clients.

## Vulnerable Application

Remote Desktop Protocol (RDP), also known as Terminal Services, allows authenticated users to remotely administer Windows workstations and servers.  RDP is common in enterprise networks, as it allows IT administrators and users alike to conveniently work remotely.  Additionally, RDP is not uncommon to see exposed to the Internet, sometimes on its default port of TCP/3389.

RDP is supported on Windows platforms from Windows XP through all modern versions of Windows.  Newer versions of Windows (XP SP3+, Vista, and up) support Network Level Authentication (NLA), which provides enhanced authentication and mitigates some RDP-based attacks.

## Verification Steps

  1. Set up a Windows target (XP, Vista, 7, 2003, 2008, 2008 R2).
  2. Start msfconsole.
  3. Load the module: `use auxiliary/scanner/rdp/cve_2019_0708_bluekeep`
  4. Specify the IP address of one or more targets: `set RHOSTS 192.168.1.1-5`
  5. Optionally, change the target port from the default of `3389`: `set RPORT 31337`
  6. Launch the scanner: `run`

## Scenarios

#### A vulnerable version and configuration of Microsoft Windows
If the target has RDP accessible with NLP disabled, and is running a vulnerable version of Windows (XP, 7, 2003, 2008, 2008 R2) without a [patch](https://support.microsoft.com/en-us/help/4500705/customer-guidance-for-cve-2019-0708), it will return a Vulnerable status:

```
[+] 192.168.1.2:3389  - The target is vulnerable.
[*] 192.168.1.2:3389  - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### A patched or NLP-enabled configuration of Microsoft Windows
If the target has RDP accessible, but is not vulnerable for one or more reasons, it may have NLP enabled or may have been [patched](https://support.microsoft.com/en-us/help/4500705/customer-guidance-for-cve-2019-0708).  In these cases, a patched or NLP-enabled target will return:

```
[*] 192.168.1.3:3389  - The target is not exploitable.
[*] 192.168.1.3:3389  - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### A non-vulnerable version of Microsoft Windows
If the target has RDP accessible, but is a newer, non-vulnerable version of Windows (8, 10, 2012, 2016), or may have been [patched](https://support.microsoft.com/en-us/help/4500705/customer-guidance-for-cve-2019-0708).  In these cases, a non-vulnerable target will return:

```
[*] 192.168.1.4:3389  - The target is not exploitable.
[*] 192.168.1.4:3389  - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### A host without RDP enabled
A non-Windows target, or a Windows target with RDP disabled or firewalled, will report failure to connect:

```
[*] 192.168.220.1:3389    - The target service is not running, or refused our connection.
[*] 192.168.220.1:3389    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Testing

This scanner module has been tested against a variety of Windows hosts, ranging from Windows XP through Windows 2016.  During testing, no adverse effects or logging was identified on release builds.  (Note: Debug/checked builds exhibited crashes, but these should not be found in production environments.)

Workstation versions:
 - Windows XP SP2 (x86), SP3 (x86), Version 2003 (x64)
 - Windows Vista SP0 (x86), SP0 (x64), SP2 (x64)
 - Windows 7 SP1 (x86), SP1 (x64)
 - Windows 10 1709, ()x64)

Server versions:
 - Windows 2000 SP4 (x86)
 - Windows 2003 SP0 (x86), SP1 (x86), SP1 (x64), SP2 (x86), R2 SP1 (x86), R2 SP2 (x86)
 - Windows 2008 SP0 (x64), SP1 (x86), R2 SP1 (x64)
 - Windows 2012 R2 (x64)
 - Windows 2016 Build 1607 (x64)

### Questions?  Issues?

If you encounter issues with the module, consider reaching out to the developers and user community [using Slack](https://www.metasploit.com/slack).  If you encounter crashing on any targets, please consider [opening a issue](https://github.com/rapid7/metasploit-framework/issues/new).
