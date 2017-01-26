## Description

This module allows you to authenticate Advantech WebAccess.

## Vulnerable Application

This module was specifically tested on versions 8.0, 8.1, and 8.2:

**8.2 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.0/AdvantechWebAccessUSANode8.0_20141103_3.4.3.exe

**8.1 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

**8.0 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.0/AdvantechWebAccessUSANode8.0_20141103_3.4.3.exe


## Verification Steps

1. Make sure Advantech WebAccess is up and running
2. Start ```msfconsole```
3. ```use auxiliary/scanner/http/advantech_webaccess_login
4. ```set RHOSTS [IP]```
5. Set credentials
6. ```run```
7. You should see that the module is attempting to log in.

