## Vulnerable Application

`vmauthd` is the VMWare authentication daemon that is included with many VMWare products, 
including [ESX(i)](https://my.vmware.com/en/web/vmware/evalcenter?p=free-esxi6), 
and [Workstation](https://www.vmware.com/products/workstation.html).

**Warning:** There is a known condition where this module utilizes `SSLv3`, however this is disabled in Kali.
Changing to `SSLv23` will work on a default Kali install.  This change was made for documenting this module.
Please see [#7225](https://github.com/rapid7/metasploit-framework/issues/7225#issuecomment-294413253) for additional details and the fix.

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/vmware/vmauthd_version`
  3. Do: `set rhosts`
  4. Do: `run`

## Scenarios

  A run against ESXi 6.0.0 Update 2 (Build 4600944)

  ```
    msf > use auxiliary/scanner/vmware/vmauthd_version 
    msf auxiliary(vmauthd_version) > set rhosts 10.1.2.5
    rhosts => 10.1.2.5
    msf auxiliary(vmauthd_version) > run
    
    [*] 10.1.2.5:902      - 10.1.2.5:902 Switching to SSL connection...
    [*] 10.1.2.5:902      - 10.1.2.5:902 Banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , VMXARGS supported, NFCSSL supported/t Certificate:/C=US/ST=California/L=Palo Alto/O=VMware, Inc/OU=VMware ESX Server Default Certificate/emailAddress=ssl-certificates@vmware.com/CN=localhost.localdomain/unstructuredName=1328954372,564d7761726520496e632e
  ```
