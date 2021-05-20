## Description

This module exploit the CVE-2021-27850 which affects several versions of Apache Tapestry. The versions concerned are at least 5.4.5, 5.5.0, 5.6.2 and 5.7.0. This CVE allows an attacker to leak the source code of a such a Tapestry server by requesting a particular .class file with its name through the url with an extra "/" at the end : http://tapestryhost:8080/assets/something/services/AppModule.class/. It makes in particular possible to leak the HMAC secret key which is located by default in AppModule.class.

## Verification Steps

List the steps needed to make sure this thing works

- 1. Start `msfconsole`
- 2. `use auxiliary/gather/http/cve_2021_27850_apache_tapestry_hmac_key`
- 3. `set RHOST <target_host>` and `set RPORT <target_port>`
- 4. `check` to check if the targeted Tapestry server is vulnerable or not
- 5. `set targeted_class` if you want to target another class than the default one (AppModule.class) 
- 6. `run` the module to exploit the CVE and leak the secret key !

## Options

**RHOSTS**

Set the target host. The default value is `localhost`.

**RPORT**

Set the target port. The default value is `8080` which is the default value used by Tapestry server.

**TARGETED_CLASS**

This is not a required option and by default the value is `AppModule.class` which is also the default java class of by Tapestry server where the hmac key is set. But in case you want to target a different java class, it can be done by setting this option with another class name.
