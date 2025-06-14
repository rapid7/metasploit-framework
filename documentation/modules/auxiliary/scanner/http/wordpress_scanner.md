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

1. Do: `use auxiliary/scanner/http/wordpress_scanner`
2. Do: `set RHOSTS [IP]`
3. Do: `set VHOST [HOSTNAME]`
4. Do: `run`

## Options

### Exploitable

Only scans for themes and plugins which Metasploit has a module for.  Defaults to `true`

### Exploitable_themes

Which list of exploitable themes to use. Default is `data/wordlists/wp-exploitable-themes.txt`

### Exploitable_plugins

Which list of exploitable plugins to use. Default is `data/wordlists/wp-exploitable-plugins.txt`

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
msf5 auxiliary(scanner/http/wordpress_scanner) > set RHOSTS msf-wp.docksal
RHOSTS => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_scanner) > set VHOST msf-wp.docksal
VHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_scanner) > run

[*] Trying 192.168.64.100
[+] 192.168.64.100 running Wordpress 5.2
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/wordpress_scanner) > 

```

### Wordpress 5.4.2 with Plugin and Theme Enumeration, Exploitable True

```
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 auxiliary(scanner/http/wordpress_scanner) > set rhosts 192.168.2.144
rhosts => 192.168.2.144
msf6 auxiliary(scanner/http/wordpress_scanner) > run

[*] Trying 192.168.2.144
[+] 192.168.2.144 - Detected Wordpress 5.4.4
[*] 192.168.2.144 - Enumerating Themes
[*] 192.168.2.144 - Progress  0/2 (0.0%)
[*] 192.168.2.144 - Finished scanning themes
[*] 192.168.2.144 - Enumerating plugins
[*] 192.168.2.144 - Progress   0/44 (0.0%)
[+] 192.168.2.144 - Detected plugin: backup version 1.5.8
[+] 192.168.2.144 - Detected plugin: simple-file-list version 4.2.2
[+] 192.168.2.144 - Detected plugin: drag-and-drop-multiple-file-upload-contact-form-7 version 1.3.3.2
[+] 192.168.2.144 - Detected plugin: loginizer version 1.6.3
[+] 192.168.2.144 - Detected plugin: email-subscribers version 4.2.2
[+] 192.168.2.144 - Detected plugin: learnpress version 3.2.6.7
[+] 192.168.2.144 - Detected plugin: boldgrid-backup version 1.14.9
[+] 192.168.2.144 - Detected plugin: easy-wp-smtp version 1.4.1
[+] 192.168.2.144 - Detected plugin: woocommerce-abandoned-cart version You
[*] 192.168.2.144 - Finished scanning plugins
[*] 192.168.2.144 - Finished all scans
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

### Wordpress 5.4.2 with Plugin and Theme Enumeration, Exploitable False

```
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 auxiliary(scanner/http/wordpress_scanner) > set rhosts 192.168.2.144
rhosts => 192.168.2.144
msf6 auxiliary(scanner/http/wordpress_scanner) > set exploitable false
exploitable => false
msf6 auxiliary(scanner/http/wordpress_scanner) > run

[*] Trying 192.168.2.144
[+] 192.168.2.144 - Detected Wordpress 5.4.4
[*] 192.168.2.144 - Enumerating Themes
[*] 192.168.2.144 - Progress      0/22140 (0.0%)
[*] 192.168.2.144 - Progress   1000/22140 (4.51%)
[*] 192.168.2.144 - Progress   2000/22140 (9.03%)
[*] 192.168.2.144 - Progress   3000/22140 (13.55%)
[*] 192.168.2.144 - Progress   4000/22140 (18.06%)
[*] 192.168.2.144 - Progress   5000/22140 (22.58%)
[*] 192.168.2.144 - Progress   6000/22140 (27.1%)
[*] 192.168.2.144 - Progress   7000/22140 (31.61%)
[*] 192.168.2.144 - Progress   8000/22140 (36.13%)
[*] 192.168.2.144 - Progress   9000/22140 (40.65%)
[*] 192.168.2.144 - Progress  10000/22140 (45.16%)
[*] 192.168.2.144 - Progress  11000/22140 (49.68%)
[*] 192.168.2.144 - Progress  12000/22140 (54.2%)
[*] 192.168.2.144 - Progress  13000/22140 (58.71%)
[*] 192.168.2.144 - Progress  14000/22140 (63.23%)
[*] 192.168.2.144 - Progress  15000/22140 (67.75%)
[*] 192.168.2.144 - Progress  16000/22140 (72.26%)
[*] 192.168.2.144 - Progress  17000/22140 (76.78%)
[*] 192.168.2.144 - Progress  18000/22140 (81.3%)
[*] 192.168.2.144 - Progress  19000/22140 (85.81%)
[+] 192.168.2.144 - Detected theme: twentynineteen version 1.5
[+] 192.168.2.144 - Detected theme: twentyseventeen version 2.3
[*] 192.168.2.144 - Progress  20000/22140 (90.33%)
[+] 192.168.2.144 - Detected theme: twentytwenty version 1.2
[*] 192.168.2.144 - Progress  21000/22140 (94.85%)
[*] 192.168.2.144 - Progress  22000/22140 (99.36%)
[*] 192.168.2.144 - Finished scanning themes
[*] 192.168.2.144 - Enumerating plugins
[*] 192.168.2.144 - Progress      0/91829 (0.0%)
[*] 192.168.2.144 - Progress   1000/91829 (1.08%)
[*] 192.168.2.144 - Progress   2000/91829 (2.17%)
[*] 192.168.2.144 - Progress   3000/91829 (3.26%)
[+] 192.168.2.144 - Detected plugin: akismet version 4.1.5
[*] 192.168.2.144 - Progress   4000/91829 (4.35%)
[*] 192.168.2.144 - Progress   5000/91829 (5.44%)
[*] 192.168.2.144 - Progress   6000/91829 (6.53%)
[+] 192.168.2.144 - Detected plugin: backup version 1.5.8
[*] 192.168.2.144 - Progress   7000/91829 (7.62%)
[*] 192.168.2.144 - Progress   8000/91829 (8.71%)
[*] 192.168.2.144 - Progress   9000/91829 (9.8%)
[+] 192.168.2.144 - Detected plugin: boldgrid-backup version 1.14.9
[*] 192.168.2.144 - Progress  10000/91829 (10.88%)
[*] 192.168.2.144 - Progress  11000/91829 (11.97%)
[*] 192.168.2.144 - Progress  12000/91829 (13.06%)
[*] 192.168.2.144 - Progress  13000/91829 (14.15%)
[*] 192.168.2.144 - Progress  14000/91829 (15.24%)
[*] 192.168.2.144 - Progress  15000/91829 (16.33%)
[+] 192.168.2.144 - Detected plugin: contact-form-7 version 5.1.9
[*] 192.168.2.144 - Progress  16000/91829 (17.42%)
[*] 192.168.2.144 - Progress  17000/91829 (18.51%)
[*] 192.168.2.144 - Progress  18000/91829 (19.6%)
[*] 192.168.2.144 - Progress  19000/91829 (20.69%)
[*] 192.168.2.144 - Progress  20000/91829 (21.77%)
[+] 192.168.2.144 - Detected plugin: drag-and-drop-multiple-file-upload-contact-form-7 version 1.3.3.2
[*] 192.168.2.144 - Progress  21000/91829 (22.86%)
[+] 192.168.2.144 - Detected plugin: duplicator version 1.3.26
[*] 192.168.2.144 - Progress  22000/91829 (23.95%)
[+] 192.168.2.144 - Detected plugin: easy-wp-smtp version 1.4.1
[*] 192.168.2.144 - Progress  23000/91829 (25.04%)
[+] 192.168.2.144 - Detected plugin: email-subscribers version 4.2.2
[*] 192.168.2.144 - Progress  24000/91829 (26.13%)
[*] 192.168.2.144 - Progress  25000/91829 (27.22%)
[*] 192.168.2.144 - Progress  26000/91829 (28.31%)
[*] 192.168.2.144 - Progress  27000/91829 (29.4%)
[*] 192.168.2.144 - Progress  28000/91829 (30.49%)
[*] 192.168.2.144 - Progress  29000/91829 (31.58%)
[*] 192.168.2.144 - Progress  30000/91829 (32.66%)
[*] 192.168.2.144 - Progress  31000/91829 (33.75%)
[+] 192.168.2.144 - Detected plugin: gotmls version 4.20.59
[*] 192.168.2.144 - Progress  32000/91829 (34.84%)
[*] 192.168.2.144 - Progress  33000/91829 (35.93%)
[*] 192.168.2.144 - Progress  34000/91829 (37.02%)
[*] 192.168.2.144 - Progress  35000/91829 (38.11%)
[*] 192.168.2.144 - Progress  36000/91829 (39.2%)
[*] 192.168.2.144 - Progress  37000/91829 (40.29%)
[+] 192.168.2.144 - Detected plugin: learnpress version 3.2.6.7
[*] 192.168.2.144 - Progress  38000/91829 (41.38%)
[*] 192.168.2.144 - Progress  39000/91829 (42.47%)
[+] 192.168.2.144 - Detected plugin: loginizer version 1.6.3
[*] 192.168.2.144 - Progress  40000/91829 (43.55%)
[*] 192.168.2.144 - Progress  41000/91829 (44.64%)
[*] 192.168.2.144 - Progress  42000/91829 (45.73%)
[*] 192.168.2.144 - Progress  43000/91829 (46.82%)
[*] 192.168.2.144 - Progress  44000/91829 (47.91%)
[*] 192.168.2.144 - Progress  45000/91829 (49.0%)
[*] 192.168.2.144 - Progress  46000/91829 (50.09%)
[*] 192.168.2.144 - Progress  47000/91829 (51.18%)
[*] 192.168.2.144 - Progress  48000/91829 (52.27%)
[*] 192.168.2.144 - Progress  49000/91829 (53.36%)
[*] 192.168.2.144 - Progress  50000/91829 (54.44%)
[*] 192.168.2.144 - Progress  51000/91829 (55.53%)
[*] 192.168.2.144 - Progress  52000/91829 (56.62%)
[*] 192.168.2.144 - Progress  53000/91829 (57.71%)
[*] 192.168.2.144 - Progress  54000/91829 (58.8%)
[*] 192.168.2.144 - Progress  55000/91829 (59.89%)
[*] 192.168.2.144 - Progress  56000/91829 (60.98%)
[*] 192.168.2.144 - Progress  57000/91829 (62.07%)
[*] 192.168.2.144 - Progress  58000/91829 (63.16%)
[*] 192.168.2.144 - Progress  59000/91829 (64.24%)
[*] 192.168.2.144 - Progress  60000/91829 (65.33%)
[*] 192.168.2.144 - Progress  61000/91829 (66.42%)
[+] 192.168.2.144 - Detected plugin: simple-file-list version 4.2.2
[*] 192.168.2.144 - Progress  62000/91829 (67.51%)
[*] 192.168.2.144 - Progress  63000/91829 (68.6%)
[*] 192.168.2.144 - Progress  64000/91829 (69.69%)
[*] 192.168.2.144 - Progress  65000/91829 (70.78%)
[*] 192.168.2.144 - Progress  66000/91829 (71.87%)
[*] 192.168.2.144 - Progress  67000/91829 (72.96%)
[*] 192.168.2.144 - Progress  68000/91829 (74.05%)
[*] 192.168.2.144 - Progress  69000/91829 (75.13%)
[*] 192.168.2.144 - Progress  70000/91829 (76.22%)
[*] 192.168.2.144 - Progress  71000/91829 (77.31%)
[*] 192.168.2.144 - Progress  72000/91829 (78.4%)
[*] 192.168.2.144 - Progress  73000/91829 (79.49%)
[*] 192.168.2.144 - Progress  74000/91829 (80.58%)
[*] 192.168.2.144 - Progress  75000/91829 (81.67%)
[*] 192.168.2.144 - Progress  76000/91829 (82.76%)
[*] 192.168.2.144 - Progress  77000/91829 (83.85%)
[*] 192.168.2.144 - Progress  78000/91829 (84.94%)
[+] 192.168.2.144 - Detected plugin: woocommerce version 4.8.0
[+] 192.168.2.144 - Detected plugin: woocommerce-abandoned-cart version You
[*] 192.168.2.144 - Progress  79000/91829 (86.02%)
[+] 192.168.2.144 - Detected plugin: wordpress-popular-posts version 5.3.2
[*] 192.168.2.144 - Progress  80000/91829 (87.11%)
[*] 192.168.2.144 - Progress  81000/91829 (88.2%)
[*] 192.168.2.144 - Progress  82000/91829 (89.29%)
[*] 192.168.2.144 - Progress  83000/91829 (90.38%)
[*] 192.168.2.144 - Progress  84000/91829 (91.47%)
[*] 192.168.2.144 - Progress  85000/91829 (92.56%)
[*] 192.168.2.144 - Progress  86000/91829 (93.65%)
[+] 192.168.2.144 - Detected plugin: wp-super-cache version 1.7.1
[*] 192.168.2.144 - Progress  87000/91829 (94.74%)
[*] 192.168.2.144 - Progress  88000/91829 (95.83%)
[*] 192.168.2.144 - Progress  89000/91829 (96.91%)
[*] 192.168.2.144 - Progress  90000/91829 (98.0%)
[*] 192.168.2.144 - Finished scanning plugins
[*] 192.168.2.144 - Finished all scans
msf6 auxiliary(scanner/http/wordpress_scanner) > notes

Notes
=====

 Time                     Host     Service  Port  Protocol  Type                                                                                 Data
 ----                     ----     -------  ----  --------  ----                                                                                 ----
 2020-12-04 19:01:18 UTC  1.1.1.1  http     80    tcp       Wordpress 5.4.2                                                                      "/"
 2020-12-05 02:16:03 UTC  1.1.1.1  http     80    tcp       Wordpress Theme: twentynineteen version 1.5                                          {}
 2020-12-05 02:16:03 UTC  1.1.1.1  http     80    tcp       Wordpress Theme: twentyseventeen version 2.3                                         {}
 2020-12-05 02:16:58 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: akismet version 4.1.5                                              {}
 2020-12-05 02:18:44 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: contact-form-7 version 5.1.9                                       {}
 2020-12-05 02:19:35 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: drag-and-drop-multiple-file-upload-contact-form-7 version 1.3.3.2  {}
 2020-12-05 02:19:58 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: email-subscribers version 4.2.2                                    {}
 2020-12-05 02:22:41 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: loginizer version 1.6.3                                            {}
 2020-12-05 02:26:05 UTC  1.1.1.1  http     80    tcp       Wordpress Plugin: simple-file-list version 4.2.2                                     {}
```
