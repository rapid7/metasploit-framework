# Description
This module scans for hosts that support the SMBv1 protocol.  It works by sending an SMB_COM_NEGOTATE request to each host specified in RHOSTS and claims that it only supports the following SMB dialects:
```PC NETWORK PROGRAM 1.0
LANMAN1.0
Windows for Workgroups 3.1a
LM1.2X002
LANMAN2.1
NT LM 0.12
```
If the SMB server has SMBv1 enabled it will respond to the request with a dialect selected.
If the SMB server does not support SMBv1 a RST will be sent.

___
# Usage

The following is an example of its usage, where x.x.x.x allows SMBv1 and y.y.y.y does not.

#### A host that does support SMBv1.

```
msf auxiliary(smb1) > use auxiliary/scanner/smb/smb1
msf auxiliary(smb1) > set RHOSTS x.x.x.x
RHOSTS => x.x.x.x
msf auxiliary(smb1) > run

[+] x.x.x.x:445        - x.x.x.x supports SMBv1 dialect.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(smb1) > services -S x.x.x.x

Services
========

host        port  proto  name  state  info
----        ----  -----  ----  -----  ----
x.x.x.x 445   tcp    smb1  open
```

#### A host that does not support SMBv1

```
msf auxiliary(smb1) > use auxiliary/scanner/smb/smb1
msf auxiliary(smb1) > set RHOSTS y.y.y.y
RHOSTS => y.y.y.y
msf auxiliary(smb1) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
___


## Options

The only option is RHOSTS, which can be specified as a single IP, hostname, or an IP range in CIDR notation or range notation.  It can also be set using hosts from the database using ```hosts -R```.