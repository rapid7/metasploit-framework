## Description

  This module will connect to a provided range of web severs and determine 
  if a .git directory is present.

## Vulnerable Application

  Any website including a accessible .git directory in the document root 
  is vulnerable. It is possible to download the git repository even, if
  directory listing is disabled. 

### Setup in Kali
  ```
  root@kali:~# 
  root@kali:~# cd /var/www/html/
  root@kali:/var/www/html# touch secrets.yml
  root@kali:/var/www/html# git init
  Initialized empty Git repository in /var/www/html/.git/
  root@kali:/var/www/html# git add secrets.yml
  root@kali:/var/www/html# git commit -m "Add server secrets"
  [master (root-commit) df89300] Add server secrets
   1 file changed, 0 insertions(+), 0 deletions(-)
   create mode 100644 secrets.yml
  ```
  
  Enable the apache server
  ```
  root@kali:~# service apache2 start
  ```

### Setup using Docker and WordPress
  ```
  git clone https://github.com/WordPress/WordPress.git
  cd WordPress
  docker run --rm -dit -p 8080:80 -v "$(pwd)":/usr/local/apache2/htdocs/ httpd:2.4
  ```

## Verification Steps

  1. Do: ```use auxiliary/scanner/http/git_scanner```
  2. Do: ```set RHOSTS [IP]```
  3. Do: ```run```

## Options

  **GIT_CONFIG**

  Check config file in .git directory (default: true)

  **GIT_INDEX**

  Check index file in .git directory (default: true)

  **TARGETURI**

  The test path to .git directory (default: `/.git/`)

  **UserAgent**

  The HTTP User-Agent sent in the request  (default: `git/1.7.9.5`)

## Scenarios

### Scenario Kali localhost
  ```
  msf5 > use auxiliary/scanner/http/git_scanner 
  msf5 auxiliary(scanner/http/git_scanner) > set RHOST 127.0.0.1
  RHOST => 127.0.0.1
  msf5 auxiliary(scanner/http/git_scanner) > run
  
  [+] http://127.0.0.1/.git/ - git repo (version 2) found with 1 files
  [+] http://127.0.0.1/.git/config - git config file found
  [+] Saved file to: /root/.msf4/loot/20191008075821_default_127.0.0.1_config_828515.txt
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/git_scanner) >
  ```

### Scenario WordPress in Docker Container
  ```
  msf5 > use auxiliary/scanner/http/git_scanner 
  msf5 auxiliary(scanner/http/git_scanner) > set RHOST 127.0.0.1
  RHOST => 127.0.0.1
  msf5 auxiliary(scanner/http/git_scanner) > set RPORT 8080
  RPORT => 8080
  msf5 auxiliary(scanner/http/git_scanner) > run
  
  [+] http://127.0.0.1:8080/.git/ - git repo (version 2) found with 2232 files
  [+] http://127.0.0.1:8080/.git/config - git config file found
  [+] Saved file to: /home/pwe/.msf4/loot/20191008151923_default_127.0.0.1_config_803302.txt
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/git_scanner) >
  ```