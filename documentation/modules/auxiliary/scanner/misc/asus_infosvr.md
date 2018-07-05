## Description

  This module discovers ASUS infosvr servers vulnerable to unauthenticated remote command execution (CVE-2014-9583).


## Vulnerable Application

  The ASUS infosvr service is enabled by default on various models of ASUS routers and listens on the LAN interface on UDP port 9999. Unpatched versions of this service allow unauthenticated remote command execution as the `root` user.

  This module broadcasts infosvr packets on UDP port 9999 in an attempt to execute the `echo` operating system command with a unique string. Vulnerable servers will execute the command and broadcast the results to `255.255.255.255` on port 9999. This module inspects broadcast traffic on port 9999 to infer vulnerable services based on the presence of the unique string.

  This module was tested successfully on an ASUS RT-N12E with firmware version 2.0.0.35.

  Numerous ASUS models are [reportedly affected](https://github.com/jduck/asus-cmd), but untested.


## Verification Steps

  To test this module, you must make sure there is at least one vulnerable infosvr service on the same network.

  1. Start `msfconsole`
  2. Do: `use auxiliary/scanner/misc/asus_infosvr`
  3. Do: `set RHOSTS [IP]` (Default: `255.255.255.255`)
  4. Do: `run`
  5. You should be notified of any vulnerable infosvr servers on the local subnet


## Scenarios

  ```
  msf > use auxiliary/scanner/misc/asus_infosvr 
  msf auxiliary(scanner/misc/asus_infosvr) > set rhosts 255.255.255.255
  rhosts => 255.255.255.255
  msf auxiliary(scanner/misc/asus_infosvr) > run

  [*] Sending requests to 1 hosts...
  [+] 10.1.1.1:9999 is VULNERABLE
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

