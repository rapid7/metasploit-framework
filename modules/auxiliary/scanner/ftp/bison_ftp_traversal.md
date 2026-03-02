## Vulnerable Application

BisonWare BisonFTP Server version 3.5 is vulnerable to a directory traversal attack. By sending a specially crafted `RETR` command containing sequential `..//.` directory traversal strings, an unauthenticated attacker can escape the FTP root directory and download arbitrary files from the remote Windows file system.

The vulnerable software and original proof of concept can be found at [Exploit-DB 38341](https://www.exploit-db.com/exploits/38341).

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/ftp/bison_ftp_traversal`
3. Do: `set RHOSTS [IP]`
4. Do: `set FTPUSER [USERNAME]` (If required, defaults to anonymous)
5. Do: `set FTPPASS [PASSWORD]` (If required, defaults to anonymous)
6. Do: `run`
7. Verify the module successfully retrieves the specified file (defaults to `boot.ini`) and saves it to your local loot directory.

## Options

### DEPTH
The number of traversal strings (`..//`) to prepend to the requested file path to ensure the Windows root directory (`C:\`) is reached. The default is `32`.

### PATH
The absolute path to the file you wish to download from the target system, relative to the root directory. For example, `boot.ini` or `windows\win.ini`. The default is `boot.ini`.

## Scenarios

### BisonWare BisonFTP Server 3.5 on Windows XP