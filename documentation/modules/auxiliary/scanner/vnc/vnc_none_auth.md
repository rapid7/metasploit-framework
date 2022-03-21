## Vulnerable Application

This module detects VNC servers that support the "None" authentication method.

### Install

TigerVNC is one of the few VNC servers that still accepts the None authentication type,
and can be installed on either Windows or Linux. Below you can find instructions for
setting up a test server on both Windows and Linux:

#### Windows

Follow https://github.com/TigerVNC/tigervnc/wiki/Setup-TigerVNC-server-(Windows) to download
the server, and install the server using the default settings. Next start `Configure VNC Service`.

Set "Session encryption" to `None` and "Authentication" to `None`. Click `Apply` and restart the service.

#### Linux

tigervncserver is available on Ubuntu 18.04 and possibly newer versions. To start the server
in a vulnerable way, run the following command:
`tigervncserver -SecurityTypes None -localhost no --I-KNOW-THIS-IS-INSECURE`

## Verification Steps

1. Do: `use auxiliary/scanner/vnc/vnc_none_auth`
2. Do: `set RHOSTS [IP]`
3. Do: `run`

## Options

## Scenarios

### TigerVNC 1.12.80 on Windows

```
msf6 > use auxiliary/scanner/vnc/vnc_none_auth
msf6 auxiliary(scanner/vnc/vnc_none_auth) > set rhosts 111.111.1.11
rhosts => 111.111.1.11
msf6 auxiliary(scanner/vnc/vnc_none_auth) > run

[*] 111.111.1.11:5900     - 111.111.1.11:5900 - VNC server protocol version: [3, 4].8
[*] 111.111.1.11:5900     - 111.111.1.11:5900 - VNC server security types supported: VeNCrypt,None
[+] 111.111.1.11:5900     - 111.111.1.11:5900 - VNC server security types includes None, free access!
[*] 111.111.1.11:5900     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### TigerVNC 1.7.0+dfsg-8ubuntu2 on Ubuntu 18.04

```
msf6 > use auxiliary/scanner/vnc/vnc_none_auth
msf6 auxiliary(scanner/vnc/vnc_none_auth) > set rhosts 111.111.1.222
rhosts => 111.111.1.222
msf6 auxiliary(scanner/vnc/vnc_none_auth) > set rport 5901
rport => 5901
msf6 auxiliary(scanner/vnc/vnc_none_auth) > run

[*] 111.111.1.222:5901    - 111.111.1.222:5901 - VNC server protocol version: [3, 4].8
[*] 111.111.1.222:5901    - 111.111.1.222:5901 - VNC server security types supported: None
[+] 111.111.1.222:5901    - 111.111.1.222:5901 - VNC server security types includes None, free access!
[*] 111.111.1.222:5901    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
