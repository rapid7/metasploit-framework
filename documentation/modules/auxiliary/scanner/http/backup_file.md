## Intro

This module scans a web server for a file name with various backup type extensions.
The list of extensions are:

1. .backup
2. .bak
3. .copy
4. .copia
5. .old
6. .orig
7. .temp
8. .txt
9. ~

## Usage

In the basic config, you'll search for the extensions on `/index.asp`, which may not be very useful.
In this scenario, we look for `/backup` instead.  On the web server, we've created the files `backup.old`,
`backup.orig`, and `backup~`.

```
msf5 > use auxiliary/scanner/http/backup_file 
msf5 auxiliary(scanner/http/backup_file) > set verbose true
verbose => true
msf5 auxiliary(scanner/http/backup_file) > set path /backup
path => /backup
msf5 auxiliary(scanner/http/backup_file) > set rhosts 192.168.2.39
rhosts => 192.168.2.39
msf5 auxiliary(scanner/http/backup_file) > run

[*] NOT Found http://192.168.2.39:80/backup.backup
[*] NOT Found http://192.168.2.39:80/backup.bak
[*] NOT Found http://192.168.2.39:80/backup.copy
[*] NOT Found http://192.168.2.39:80/backup.copia
[+] Found http://192.168.2.39:80/backup.old
[+] Found http://192.168.2.39:80/backup.orig
[*] NOT Found http://192.168.2.39:80/backup.temp
[*] NOT Found http://192.168.2.39:80/backup.txt
[+] Found http://192.168.2.39:80/backup~
[*] NOT Found http://192.168.2.39:80/.backup.swp
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```