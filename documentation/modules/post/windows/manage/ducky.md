## Overview

This module serves as a wrapper around keyboard_send and keyevent_send using familiar Ducky Script language.

## Script Language
- **STRING** - This uses keyboard_send to send a string.
- **STRINGLN** - This sends a complete string followed by a new line.
- **GUI** - This executes the run dialog by sending keyevents for Windows+R.
- **KEYEVENT** - This allows for specific keycodes to be sent with specific key actions (press, down, and up).

### Example Script
```
GUI
STRINGLN notepad.exe
KEYEVENT 82 press
KEYEVENT 79 press
KEYEVENT 79 press
KEYEVENT 77 press
```
OR
```
GUI
STRINGLN notepad.exe
STRING This is a test.
```

## Options
- **FILENAME** - This is the file you'd like to load keystrokes from.
- **SLEEP** - Time in seconds between each line's execution.

## Basic Usage

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/manage/ducky`
4. Do: `set SESSION <session id>`
5. Do: `set FILENAME <full-path of script file>`
6. Do: `run`

### Example Usage

```
msf6 > use post/windows/manage/ducky
msf6 post(windows/manage/ducky) > set session 1
session => 1
msf6 post(windows/manage/ducky) > set FILENAME /tmp/test.txt
FILENAME => /tmp/test.txt
msf6 post(windows/manage/ducky) > set sleep 1
sleep => 1
msf6 post(windows/manage/ducky) > set VERBOSE false
VERBOSE => true
msf6 post(windows/manage/ducky) > run

[+] Reading file /tmp/test.txt
[*] Post module execution completed
```