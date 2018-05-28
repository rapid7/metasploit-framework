## Description

This module scans one or more web servers for interesting directories that can be further explored.

## Verfication Steps

1. Do: ```use auxiliary/scanner/http/dir_scanner```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/http/dir_scanner
msf auxiliary(dir_scanner) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(dir_scanner) > run

[*] Using code '404' as not found for 192.168.1.201
[*] Found http://192.168.1.201:80/.../ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/Joomla/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/cgi-bin/ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/error/ 403 (192.168.1.201)
[*] Found http://192.168.1.201:80/icons/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/oscommerce/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/phpmyadmin/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/security/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/webalizer/ 200 (192.168.1.201)
[*] Found http://192.168.1.201:80/webdav/ 200 (192.168.1.201)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_scanner) >
```

## Confirming

The following are other industry tools which can also be used.  Note that the targets are not the same as those used in the previous documentation.

### [dirb](http://dirb.sourceforge.net/)

```
# dirb http://192.168.2.137 /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 24 12:56:40 2018
URL_BASE: http://192.168.2.137/
WORDLIST_FILES: /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt

-----------------

GENERATED WORDS: 2351

---- Scanning URL: http://192.168.2.137/ ----
==> DIRECTORY: http://192.168.2.137/.../
==> DIRECTORY: http://192.168.2.137/Joomla/
==> DIRECTORY: http://192.168.2.137/cgi-bin/
==> DIRECTORY: http://192.168.2.137/error/
==> DIRECTORY: http://192.168.2.137/icons/
==> DIRECTORY: http://192.168.2.137/oscommerce/
==> DIRECTORY: http://192.168.2.137/phpmyadmin/
==> DIRECTORY: http://192.168.2.137/security/
==> DIRECTORY: http://192.168.2.137/webalizer/
==> DIRECTORY: http://192.168.2.137/webdav/
```
