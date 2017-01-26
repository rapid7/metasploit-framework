## Description

This module allows you to log into Advantech WebAccess, and gather credentials from the user list.


## Vulnerable Application

Version 8.1 was tested during development:

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

8.2 is not vulnerable to this.

## Verification Steps

1. Start msfconsole
2. ```use auxiliary/gahter/advantech_webaccess_creds```
3. ```set WEBACCESSUSER [USER]```
4. ```set WEBACCESSPASS [PASS]```
5. ```run```

## Options

**WEBACCESSUSER**

The username to use to log into Advantech WebAccess. By default, there is a built-in account
```admin``` that you could use.

**WEBACCESSPASS**

The password to use to log into AdvanTech WebAccess. By default, the built-in account ```admin```
does not have a password, which could be something you can use.
