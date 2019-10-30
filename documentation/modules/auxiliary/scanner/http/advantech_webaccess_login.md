## Description

This module allows you to authenticate to Advantech WebAccess.

## Vulnerable Application

This module was specifically tested on versions 8.0, 8.1, and 8.2:

**8.2 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.0/AdvantechWebAccessUSANode8.0_20141103_3.4.3.exe

**8.1 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

**8.0 Download**

http://advcloudfiles.advantech.com/web/Download/webaccess/8.0/AdvantechWebAccessUSANode8.0_20141103_3.4.3.exe

Note:

By default, Advantech WebAccess comes with a built-in account named ```admin```, with a blank
password.


## Verification Steps

1. Make sure Advantech WebAccess is up and running
2. Start ```msfconsole```
3. ```use auxiliary/scanner/http/advantech_webaccess_login```
4. ```set RHOSTS [IP]```
5. Set credentials
6. ```run```
7. You should see that the module is attempting to log in.

## Demo

![webaccess_login_demo](https://cloud.githubusercontent.com/assets/1170914/22352301/26549236-e3e1-11e6-9710-506166a8bee3.gif)
