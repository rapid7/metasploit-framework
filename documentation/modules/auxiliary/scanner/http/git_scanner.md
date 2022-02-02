## Vulnerable Application

This module looks for a `.git` folder on a web server, and attempts to read the `config` and `index` files to gather information about the repo.

### Environment

On Kali, we can clone metasploit into the apache folder to create a vulnerable environment.

```
root@kali:~# cd /var/www/html/
root@kali:/var/www/html# git clone https://github.com/rapid7/metasploit-framework.git
Cloning into 'metasploit-framework'...
remote: Enumerating objects: 49, done.
remote: Counting objects: 100% (49/49), done.
remote: Compressing objects: 100% (41/41), done.
remote: Total 509870 (delta 18), reused 20 (delta 8), pack-reused 509821
Receiving objects: 100% (509870/509870), 415.71 MiB | 8.61 MiB/s, done.
Resolving deltas: 100% (372897/372897), done.
Updating files: 100% (10064/10064), done.
root@kali:/var/www/html# service apache2 start
```

## Verification Steps

  1. Install a git repo in a web server
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/git_scanner```
  4. Do: ```set rhosts [ip]```
  5. Do: ```run```
  6. You should get information about the git repo

## Options

  **GIT_CONFIG**

  Attempts to locate the `config` file, which may contain useful information.  Default is `true`.

  **GIT_INDEX**

  Attempts to locate the `index` file, which identifies the git version and number of files.  Default is `true`.

  **TARGETURI**

  Where the `.git` folder is located.  Default is `/.git/`

  **UserAgent**

  The user agent to emulate.  Default is `git/1.7.9.5`.

## Scenarios

### Metasploit git on Kali

```
msf5 > use auxiliary/scanner/http/git_scanner 
msf5 auxiliary(scanner/http/git_scanner) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/http/git_scanner) > set TARGETURI /metasploit-framework/.git/
TARGETURI => /metasploit-framework/.git/
msf5 auxiliary(scanner/http/git_scanner) > run

[+] http://127.0.0.1/metasploit-framework/.git/ - git repo (version 2) found with 10064 files
[+] http://127.0.0.1/metasploit-framework/.git/config - git config file found
[+] Saved file to: /root/.msf4/loot/20191007202314_default_127.0.0.1_config_236738.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
