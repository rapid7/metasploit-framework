## Intro

This module scans for Joomla Content Management System running on a web server for the following pages:

 1. `robots.txt`
 2. `administrator/index.php`
 3. `admin/`
 4. `index.php/using-joomla/extensions/components/users-component/registration-form`
 5. `index.php/component/users/?view=registration`
 6. `htaccess.txt`
 

## Usage

```
msf5 > use auxiliary/scanner/http/joomla_pages 
msf5 auxiliary(scanner/http/joomla_pages) > set rhosts 192.168.2.39
rhosts => 192.168.2.39
msf5 auxiliary(scanner/http/joomla_pages) > run

[+] Page Found: /robots.txt
[+] Page Found: /administrator/index.php
[+] Page Found: /htaccess.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
