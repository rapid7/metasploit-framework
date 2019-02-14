## Description

This module will connect to a provided range of web severs and determine if directory listings are enabled on them.

## Vulnerable Application

This module has been verified against the web server listed below.

### Mock Vulnerable Server

These instructions will create a web sever using `apache` with directory listing vulnerability enabled on it.

#### Setup

1. Create the `.htaccess` file with the vulnerable configuration: `echo 'Options +Indexes' > /var/www/html/.htaccess`
2. Start the apache server `service apache2 start`.

#### Note 

Make sure you dont have an `index.html` file in your `/var/www/html` for the vulnerability to work.


## Verification Steps

1. Do: ```use auxiliary/scanner/http/dir_listing```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

### Against the Mock server listed above

```
msf > use auxiliary/scanner/http/dir_listing
msf auxiliary(scanner/http/dir_listing) > set RHOSTS 1.1.1.10-14
RHOSTS => 1.1.1.10-14
msf auxiliary(scanner/http/dir_listing) > set THREADS 4
THREADS => 4
msf auxiliary(scanner/http/dir_listing) > set verbose true
verbose => true
msf auxiliary(scanner/http/dir_listing) > run

[-] The connection was refused by the remote host (1.1.1.13:80).
[*] NOT Vulnerable to directory listing http://1.1.1.13:80/
[-] The connection was refused by the remote host (1.1.1.12:80).
[*] NOT Vulnerable to directory listing http://1.1.1.12:80/
[*] NOT Vulnerable to directory listing http://1.1.1.11:80/
[*] Scanned 3 of 4 hosts (75% complete)
[+] Found Directory Listing http://1.1.1.14:80/
[*] Scanned 4 of 4 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/dir_listing) >
```
