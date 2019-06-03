## Description

This module exploits three vulnerabilities in Advantech WebAccess.

The first vulnerability is the ability for an arbitrary user to access the admin user list page,
revealing the username of every user on the system.

The second vulnerability is the user edit page can be accessed loaded by an arbitrary user, with
the data of an arbitrary user.

The final vulnerability exploited is that the HTML Form on the user edit page contains the user's
plain text password in the masked password input box. Typically the system should replace the
actual password with a masked character such as "*".


## Vulnerable Application

Version 8.1 was tested during development:

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

8.2 is not vulnerable to this.

## Verification Steps

1. Start msfconsole
2. ```use auxiliary/gather/advantech_webaccess_creds```
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


## Demo

![webaccess_steal_creds](https://cloud.githubusercontent.com/assets/1170914/22353246/34b2045e-e3e5-11e6-992c-f3ab9dcbe716.gif)
