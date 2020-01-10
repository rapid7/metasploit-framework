## Creating A Testing Environment

To use this module you need an administrative Meterpreter or shell session on a Windows 10, 1809 release or higher.

This module has been tested against:

  1. Windows 10, 1903.

This module was not tested against, but may work against:

  1. Windows 10, 1809 and above.

Versions prior to Windows 10 are not supported.

## Module Options
- **INSTALL_SERVER** - Install OpenSSH.Server for Windows (default: true)
- **INSTALL_CLIENT** - Install OpenSSH.Client for Windows (default: true)
- **UNINSTALL_SERVER** - Uninstall OpenSSH.Server for Windows (default: false)
- **UNINSTALL_CLIENT** - Uninstall OpenSSH.Client for Windows (default: false)
- **SERVER_VER** - OpenSSH.Server version (default "OpenSSH.Server~~~~0.0.1.0")
- **CLIENT_VER** - OpenSSH.Client version (default "OpenSSH.Client~~~~0.0.1.0")
- **AUTOSTART** - Sets sshd service to startup automatically at system boot for persistence (default: true)

### Verification Steps

  1. Start msfconsole
  2. Obtain a meterpreter or shell session
  3. Do: `use post/windows/manage/install_ssh`
  4. Do: `set session #`
  5. Do: `run`
  6. Open a new terminal and test SSH access: `ssh user@10.10.10.10`

## Scenarios

### Install OpenSSH on Windows

```
  msf5 > use post/windows/manage/install_ssh 
  msf5 post(windows/manage/install_ssh) > set SESSION 1 
  SESSION => 1
  msf5 post(windows/manage/install_ssh) > exploit 

  [*] Installing OpenSSH.Server
  [*] Installing OpenSSH.Client
  [*] Post module execution completed
```

Utilities such as ssh, sftp, and sshfs may be used over the Windows SSH session.
When combined with capabilities such as SSH forwarding, SSH on Windows can provide pentesters excellent utility and flexibility.

### Uninstall OpenSSH on Windows

```
  msf5 > use post/windows/manage/install_ssh 
  msf5 post(windows/manage/install_ssh) > set SESSION 1 
  SESSION => 1
  msf5 post(windows/manage/install_ssh) > set INSTALL_CLIENT false 
  INSTALL_CLIENT => false
  msf5 post(windows/manage/install_ssh) > set INSTALL_SERVER false 
  INSTALL_SERVER => false
  msf5 post(windows/manage/install_ssh) > set UNINSTALL_CLIENT true 
  UNINSTALL_CLIENT => true
  msf5 post(windows/manage/install_ssh) > set UNINSTALL_SERVER true 
  UNINSTALL_SERVER => true
  msf5 post(windows/manage/install_ssh) > exploit 

  [*] Uninstalling OpenSSH.Server
  [*] Uninstalling OpenSSH.Client
  [*] Post module execution completed
```
