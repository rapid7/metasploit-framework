## Vulnerable Application

This module allows you to test if a web server (or web application) is vulnerable to directory traversal.

### Setup

1. Install php and apache on your machine
1. Remove everything in /var/www/html/
1. Create `/var/www/html/index.php` with the following contents
    ```
    <?php
    $p = 'home.php';
    if (isset($_GET['p']))
        $p = $_GET['p'];
    include ($p);
    ?>
    ```
1. Create `/var/www/html/home.php` with the following contents
    ```
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hello, World!</title>
    </head>
    <body>
        <a href="?p=home.php">home</a>
    </body>
    </html>
    ```
1. Run the following command: `sudo systemctl start apache2.service`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/http_traversal`
1. Do: `set rhosts <rhost>`
1. Do: `set path <filepath>`
1. Do: `run`

## Options

### DATA

HTTP body data to send in the request

### DEPTH

Directory traversal depth (default: `5`)

### FILELIST

File containing list of files to bruteforce for (default: `/usr/share/metasploit-framework/data/wordlists/sensitive_files.txt`)

### METHOD

HTTP request method to use (default: `GET`)

### PATH

Vulnerable path. Ex: /foo/index.php?pg= (default: `/`)

### PATTERN

Regexp pattern to determine successful directory traversal (default: `^HTTP/\d\.\d 200`)

## Scenarios

### Apache/2.4.57 on Kali GNU/Linux Rolling 2023.3

```
msf6 > use auxiliary/scanner/http/http_traversal
msf6 auxiliary(scanner/http/http_traversal) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/http_traversal) > set path /?p=
path => /?p=
msf6 auxiliary(scanner/http/http_traversal) > run

[*] Running action: CHECK...
[+] Found trigger: ../
[+] Directory traversal found: ../
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
