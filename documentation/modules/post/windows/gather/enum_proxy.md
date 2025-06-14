## Vulnerable Application

This module pulls a user's proxy settings. If neither RHOST or SID
are set it pulls the current user, else it will pull the user's settings
for the specified SID and target host.


## Verification Steps

1. Start msfconsole
1. Get a session on a Windows host
1. Do: `use post/windows/gather/enum_proxy`
1. Do: `set session <session id>`
1. Do: `run`
1. You should receive system proxy information


## Options

### RHOST

Remote host to clone settings to (defaults to local)

### SID

SID of user to clone settings to (SYSTEM is S-1-5-18) (default: blank)


## Scenarios

### Windows Server 2016 (x86_64)

```
msf6 > use post/windows/gather/enum_proxy
msf6 post(windows/gather/enum_proxy) > set session 1
session => 1
msf6 post(windows/gather/enum_proxy) > run

[*] Proxy Counter = 3
[*] Setting: WPAD and Proxy server
[*] Proxy Server: http=127.0.0.1:80;https=127.0.0.1:80;ftp=127.0.0.1:80
[*] Post module execution completed
```

### Windows 7 SP1 (x86_64)

```
msf6 > use post/windows/gather/enum_proxy
msf6 post(windows/gather/enum_proxy) > set session 1
session => 1
msf6 post(windows/gather/enum_proxy) > run

[*] Proxy Counter = 77
[*] Setting: WPAD, Proxy server and AutoConfigure script
[*] Proxy Server: http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080
[*] AutoConfigURL: http://corp.local/wpad.dat
[*] Post module execution completed
msf6 post(windows/gather/enum_proxy) > 
```
