## Vulnerable Application

IBM Data Risk Manager (IDRM) contains two vulnerabilities that can be chained by an unauthenticated attacker to download arbitrary files off the system.
The first is an unauthenticated bypass, followed by a path traversal.
This module exploits both vulnerabilities, giving an attacker the ability to download (non-root) files.
A downloaded file is zipped, and this module also unzips it before storing it in the database.
By default, this module downloads Tomcat's application.properties file, which contains the database password, amongst other sensitive data.
At the time of disclosure, this is was a 0 day, but IBM later patched it and released their advisory. 
Versions 2.0.2 to 2.0.4 are vulnerable, version 2.0.1 is not.

### Vulnerability information
For more information about the vulnerability check the advisory at:
https://github.com/pedrib/PoC/blob/master/advisories/IBM/ibm\_drm/ibm\_drm\_rce.md

### Setup

The application is available to download as a Linux virtual appliance from IBM's website. You need to have a valid IBM contract to be able to do so.

## Verification Steps

Module defaults work very well, you should just need to set `RHOST` and the `FILEPATH` you want to download.

## Scenarios

A successful exploit will look like this:

```
msf5 auxiliary(admin/http/ibm_drm_file_download) > run

[+] 10.9.8.213:8443 - Successfully "stickied" our session ID kmhleyPh
[+] 10.9.8.213:8443 - We have obtained a new admin password 28010e88-6ffb-46e9-90d6-2ded732120d1
[+] 10.9.8.213:8443 - We're now authenticated as admin!
[+] File saved in: /home/conta/.msf4/loot/20200421154045_default_10.9.8.213_IBM_DRM.http_402604.bin
[*] Auxiliary module execution completed
```

- Verify that the file was saved in the location specified.
