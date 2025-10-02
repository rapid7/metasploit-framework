## Description
This module will scan given instances for an unauthenticated SQL injection
within the CP Multi-View Calendar plugin v1.1.4 for Wordpress.

## References
* [https://wordpress.org/plugins/cp-multi-view-calendar/]

## Vulnerable Application

### Setup using Docksal
Install [Docksal](https://docksal.io/)

Create a new Wordpress installation using `fin project create`

```
➜  ~ fin project create                  
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
➜  ~ 
```

Download the Wordpress plugin

```
cd msf-wp/wp-content/plugins
wget https://github.com/wp-plugins/cp-multi-view-calendar/archive/refs/tags/1.0.2.zip
unzip 1.0.2.zip
```

Login and click on DukaPress "Activate" Link

```
http://msf-wp.docksal/wp-admin/plugins.php
user: admin
pass: admin
```

## Verification Steps

1. Do: ```use auxiliary/scanner/http/press_cp_calendar_sqli```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set VHOST [HOSTNAME]```
4. Do: ```run```

## Options

### TARGETURI**

Target URI of the Wordpress instance
