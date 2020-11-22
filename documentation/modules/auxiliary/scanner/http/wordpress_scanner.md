## Vulnerable Application

Detects Wordpress installations and their version number.
Also, optionally, detects themes and plugins.

### Setup using Docksal

Install [Docksal](https://docksal.io/)

Create a new WordPress installation using `fin project create`

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

## Verification Steps

1. Do: `use auxiliary/scanner/http/wordpress_sanner`
2. Do: `set RHOSTS [IP]`
3. Do: `set VHOST [HOSTNAME]`
4. Do: `run`

## Options

### PLUGINS

If plugins should be scanned. Defaults to `true`

### PLUGINS_FILE

Which plugins list to use. Default is `data/wordlists/wp-plugins.txt`

### THEMES

If themes should be scanned. Defaults to `true`

### THEMES_FILE

Which themes list to use. Default is `data/wordlists/wp-themes.txt`

### Progress

How often to print a prorgress bar while scanning for themes/plugins.  Defaults to `1000`

## Scenarios

### Wordpress 5.2 running in Docksal

Follow the Instructions above to setup the Docksal Containers.

```
msf5 > use auxiliary/scanner/http/wordpress_scanner
msf5 auxiliary(scanner/http/wordpress_scanner) > set RHOST msf-wp.docksal
RHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_scanner) > set VHOST msf-wp.docksal
VHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_scanner) > run

[*] Trying 192.168.64.100
[+] 192.168.64.100 running Wordpress 5.2
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/wordpress_scanner) > 

```

### Wordpress 5.4.2 with Pluin and Theme Enumeration

```
msf6 > use auxiliary/scanner/http/wordpress_scanner 
msf6 auxiliary(scanner/http/wordpress_scanner) > set rhosts 192.168.2.144
rhosts => 192.168.2.144
msf6 auxiliary(scanner/http/wordpress_scanner) > run

[*] Trying 192.168.2.144
[+] 192.168.2.144 running Wordpress 5.4.2
[*] Enumerating Themes
[*] Progress 0/19226 (0.0%)
[*] Progress 1000/19226 (5.2%)
[*] Progress 2000/19226 (10.4%)
[*] Progress 3000/19226 (15.6%)
[*] Progress 4000/19226 (20.8%)
[*] Progress 5000/19226 (26.0%)
[*] Progress 6000/19226 (31.2%)
[*] Progress 7000/19226 (36.4%)
[*] Progress 8000/19226 (41.61%)
[*] Progress 9000/19226 (46.81%)
[*] Progress 10000/19226 (52.01%)
[*] Progress 11000/19226 (57.21%)
[*] Progress 12000/19226 (62.41%)
[*] Progress 13000/19226 (67.61%)
[*] Progress 14000/19226 (72.81%)
[*] Progress 15000/19226 (78.01%)
[*] Progress 16000/19226 (83.22%)
[*] Progress 17000/19226 (88.42%)
[+] Detected Theme: twentynineteen version 1.5 
[+] Detected Theme: twentyseventeen version 2.3 
[*] Progress 18000/19226 (93.62%)
[*] Progress 19000/19226 (98.82%)
[*] Enumerating Plugins
[*] Progress 0/80624 (0.0%)
[*] Progress 1000/80624 (1.24%)
[*] Progress 2000/80624 (2.48%)
[+] Detected Plugin: akismet version 4.1.5 
[*] Progress 3000/80624 (3.72%)
[*] Progress 4000/80624 (4.96%)
[*] Progress 5000/80624 (6.2%)
[*] Progress 6000/80624 (7.44%)
[*] Progress 7000/80624 (8.68%)
[*] Progress 8000/80624 (9.92%)
[*] Progress 9000/80624 (11.16%)
[*] Progress 10000/80624 (12.4%)
[*] Progress 11000/80624 (13.64%)
[*] Progress 12000/80624 (14.88%)
[*] Progress 13000/80624 (16.12%)
[+] Detected Plugin: contact-form-7 version 5.1.9 
[*] Progress 14000/80624 (17.36%)
[*] Progress 15000/80624 (18.6%)
[*] Progress 16000/80624 (19.84%)
[*] Progress 17000/80624 (21.08%)
[*] Progress 18000/80624 (22.32%)
[+] Detected Plugin: drag-and-drop-multiple-file-upload-contact-form-7 version 1.3.3.2 
[*] Progress 19000/80624 (23.56%)
[*] Progress 20000/80624 (24.8%)
[+] Detected Plugin: email-subscribers version 4.2.2 
[*] Progress 21000/80624 (26.04%)
[*] Progress 22000/80624 (27.28%)
[*] Progress 23000/80624 (28.52%)
[*] Progress 24000/80624 (29.76%)
[*] Progress 25000/80624 (31.0%)
[*] Progress 26000/80624 (32.24%)
[*] Progress 27000/80624 (33.48%)
[*] Progress 28000/80624 (34.72%)
[*] Progress 29000/80624 (35.96%)
[*] Progress 30000/80624 (37.2%)
[*] Progress 31000/80624 (38.45%)
[*] Progress 32000/80624 (39.69%)
[*] Progress 33000/80624 (40.93%)
[*] Progress 34000/80624 (42.17%)
[*] Progress 35000/80624 (43.41%)
[+] Detected Plugin: loginizer version 1.6.3 
[*] Progress 36000/80624 (44.65%)
[*] Progress 37000/80624 (45.89%)
[*] Progress 38000/80624 (47.13%)
[*] Progress 39000/80624 (48.37%)
[*] Progress 40000/80624 (49.61%)
[*] Progress 41000/80624 (50.85%)
[*] Progress 42000/80624 (52.09%)
[*] Progress 43000/80624 (53.33%)
[*] Progress 44000/80624 (54.57%)
[*] Progress 45000/80624 (55.81%)
[*] Progress 46000/80624 (57.05%)
[*] Progress 47000/80624 (58.29%)
[*] Progress 48000/80624 (59.53%)
[*] Progress 49000/80624 (60.77%)
[*] Progress 50000/80624 (62.01%)
[*] Progress 51000/80624 (63.25%)
[*] Progress 52000/80624 (64.49%)
[*] Progress 53000/80624 (65.73%)
[*] Progress 54000/80624 (66.97%)
[*] Progress 55000/80624 (68.21%)
[+] Detected Plugin: simple-file-list version 4.2.2 
[*] Progress 56000/80624 (69.45%)
[*] Progress 57000/80624 (70.69%)
[*] Progress 58000/80624 (71.93%)
[*] Progress 59000/80624 (73.17%)
[*] Progress 60000/80624 (74.41%)
[*] Progress 61000/80624 (75.65%)
[*] Progress 62000/80624 (76.9%)
[*] Progress 63000/80624 (78.14%)
[*] Progress 64000/80624 (79.38%)
[*] Progress 65000/80624 (80.62%)
[*] Progress 66000/80624 (81.86%)
[*] Progress 67000/80624 (83.1%)
[*] Progress 68000/80624 (84.34%)
[*] Progress 69000/80624 (85.58%)
[*] Progress 70000/80624 (86.82%)
[*] Progress 71000/80624 (88.06%)
[*] Progress 72000/80624 (89.3%)
[*] Progress 73000/80624 (90.54%)
[*] Progress 74000/80624 (91.78%)
[*] Progress 75000/80624 (93.02%)
[*] Progress 76000/80624 (94.26%)
[*] Progress 77000/80624 (95.5%)
[*] Progress 78000/80624 (96.74%)
[*] Progress 79000/80624 (97.98%)
[*] Progress 80000/80624 (99.22%)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
