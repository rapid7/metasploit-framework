## Vulnerable Application

### Description

This module checks to see whether or not the scanned systems return the HSTS header to enforce HSTS.

### Install on Ubuntu 18.04 LTS

    sudo apt-get install apache2
    sudo service apache2 start
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

Once this is done place the following content into `/etc/apache2/conf-available/ssl-params.conf`:

    # from https://cipherli.st/
    # and https://raymii.org/s/tutorials/Strong_SSL_Security_On_Apache2.html
    
    SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
    SSLProtocol All -SSLv2 -SSLv3
    SSLHonorCipherOrder On
    # Disable preloading HSTS for now.  You can use the commented out header line that includes
    # the "preload" directive if you understand the implications.
    #Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains; preload"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    # Requires Apache >= 2.4
    SSLCompression off
    SSLSessionTickets Off
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

    SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"

Then execute the following:

    sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak

Place the following in `/etc/apache2/sites-available/default-ssl.conf`:

```
&lt;IfModule mod_ssl.c>
    &lt;VirtualHost _default_:443>
        ServerAdmin webmaster@localhost

        DocumentRoot /var/www/html
    
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        SSLEngine on
        SSLCertificateFile	/etc/ssl/certs/apache-selfsigned.crt
        SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
    
        &lt;FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        &lt;/FilesMatch>
        &lt;Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        &lt;/Directory>
    
        BrowserMatch "MSIE [2-6]" \
            nokeepalive ssl-unclean-shutdown \
            downgrade-1.0 force-response-1.0
    &lt;/VirtualHost>
&lt;/IfModule>
```

Place the following in `/etc/apache2/sites-available/000-default.conf`:

    &lt;VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
    
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    
    &lt;/VirtualHost>

Finally, execute the following commands:

    sudo service apache2 stop
    sudo a2enmod ssl
    sudo a2enmod headers
    sudo a2ensite default-ssl
    sudo a2enconf ssl-params
    sudo apache2ctl configtest
    sudo service apache2 restart

## Verification Steps

1. Do: ```use auxiliary/scanner/http/http_hsts```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Options

## Scenarios

### Apache 2.4.29 on Ubuntu 18.04 LTS

Install using following instructions for Ubuntu listed above.

```
msf5 > use auxiliary/scanner/http/http_hsts
msf5 auxiliary(scanner/http/http_hsts) > set RHOSTS 192.168.90.91
RHOSTS => 192.168.90.91
msf5 auxiliary(scanner/http/http_hsts) > run

[+] 192.168.90.91:443 - Strict-Transport-Security:max-age=63072000; includeSubdomains
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/http_hsts) >

```

### Confirming using Nmap

```
tekwizz123@DESKTOP-VF1AJQB:~$ nmap 192.168.90.91 -p 443 --script http-security-headers

Starting Nmap 7.60 ( https://nmap.org ) at 2020-03-31 00:30 CDT
Nmap scan report for 192.168.90.91
Host is up (0.0034s latency).

PORT    STATE SERVICE
443/tcp open  https
| http-security-headers:
|   Strict_Transport_Security:
|     Header: Strict-Transport-Security: max-age=63072000; includeSubdomains
|   X_Frame_Options:
|     Header: X-Frame-Options: DENY
|     Description: The browser must not display this content in any frame.
|   X_Content_Type_Options:
|     Header: X-Content-Type-Options: nosniff
|_    Description: Will prevent the browser from MIME-sniffing a response away from the declared content-type.

Nmap done: 1 IP address (1 host up) scanned in 1.25 seconds
```
