# Vulnerable Application

Planyo Online Reservation System plugin of Wordpress before and including 3.0, fails to validate the scheme of the URL supplied via the ulap\_url parameter of its AJAX proxy ulap.php. This leads to a Server Side Request Forgery (SSRF) vulnerability which allows unauthenticated attackers to retrieve local files containing sensitive information and enumerate internal services.

This module uses this vulnerability to retrieve the contents of arbitrary local files by supplying a file:// URL to ulap.php.

Pre-requisites
- Docker and Docker compose installed.

## Setup

1. Create a home directory
```
mkdir wordpress-docker
cd wordpress-docker
```
2. Create a docker-compose.yml file
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
3. Start the container
```
sudo docker-compose up -d
```
4. Download the vulnerable plugin and copy to relevant folder
```
svn checkout https://plugins.svn.wordpress.org/planyo-online-reservation-system/tags/2.9/
sudo docker cp planyo-online-reservation-system wordpress:/var/www/html/wp-content/plugins/
``` 
5. Complete Wordpress Installation
- Navigate to http://localhost:8080 and complete Wordpress installation by creating an admin user.
6. Activate the plugin
- Log into admin dashboard at http://?
- On the left hand menu, select Plugins-\> Installed Plugins
- Locate the planyo plugin and click on Activate

## Verification Steps
1. Launch Metasploit
```
msfconsole
```
2. Load the Planyo LFI scanner
```
use auxiliary/gather/wp_planyo_lfi_cve_2026_3576
set RHOSTS 127.0.0.1
set RPORT 80
set TARGETURI /
```
3. Run the module
```
run
```
4. Observe output
The module should:
- Check if the target has installed the plugin
- If the plugin is installed, check if the installed version is vulnerable
- Retrieve the file and save it locally

## Options

- TARGETURI(`/`): Base path to Wordpress
- FILEPATH(`/etc/passwd`): Path of local file to download

## Scenarios

 
