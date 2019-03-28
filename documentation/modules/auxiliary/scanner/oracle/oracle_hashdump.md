## Preparation: 6 steps

  0. Oracle DB XE (Express Edition) can be downloaded for free [here](https://www.oracle.com/technetwork/database/database-technologies/express-edition/downloads/index.html).
  1. Install Oracle Database and create a database. Versions 8i through 12c are supported.
  2. On your Oracle DB machine, make sure you can ping the DB server using the `tnsping [SID]` command. If `tnsping` is not in your path upon installation, you will have to locate it manually. On a Windows machine, for Oracle 11g, `tnsping.exe` is located at: `oracle_install\app\oracle\product\<version, ie 11.2.0)\server\bin\tnsping.exe`. For 12c and 18c, it is located at `%ORACLE_HOME%\bin\tnsping.exe`. After this command is run, if all is well, the output will look something like this (note the OK echoed at the end):
```
C:> tnsping staticdb
...

Used TNSNAMES adapter to resolve the alias
Attempting to contact (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521)) (CONNECT_DATA = (SERVER = DEDICATED) (SERVICE_NAME = staticdb)))
OK (0 msec)
```
If `tnsping` fails, make sure the listener is setup correctly. See [this Oracle doc](https://docs.oracle.com/cd/E11882_01/network.112/e41945/listenercfg.htm#NETAG294) for more information about its configuration. 
  3. Make sure to create a user on the DB that has a known password, and sufficient privileges to select any table. This is necessary for getting the hashes.
  4. Test that the module's hash query works locally. Once your user is created with sufficient privileges, connect to the DB as the user, and proceed to run this query if on 12c:
     `SELECT name, spare4 FROM sys.user$ where password is not null and name <> \'ANONYMOUS\'` and this query if running an older version: `SELECT name, password FROM sys.user$ where password is not null and name<> \'ANONYMOUS\'`
  5. Set up your MSF environment to support Oracle. You need gem ruby-oci8, as well as Oracle Instant Client. [View the setup tutorial here](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux)
  6. Make sure you have a database connected to MSF (postgresql). This can be done through `msfdb` tool or through `db_connect` command in `msfconsole`.

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Start `msfconsole`
  2. Do: ```use auxiliary/scanner/oracle/oracle_hashdump.rb```
  3. Do: ```run```
  4. If Oracle DB version is supported, the query will be attempted to get the hashes. Hash table is built and then saved as credentials.
  5. You may view saved credentials with `creds` command. These are used for cracking by module `jtr_oracle_fast`.

## Options
  **DBPASS**
  The password to authenticate with. Change this from TIGER to the password of the privileged user created in step 3 of Preparation.

  **DBUSER**
  The username to authenticate with. Change this from SCOTT to the user you created who is granted privileges to select from the sys.user$ table

  **RHOST**
  The Oracle host. Change this to the IP address of the DB server.

  **RHOSTS**
  The target address range or CIDR identifier. If no CIDR notation is necessary, keep this value the same as RHOST.

  **RPORT**
  The TNS port of the Oracle DB server. By default, Oracle uses port 1521. Double-check the port of your Oracle DB.

  **SID**
  The Service ID (of the database) to authenticate with. Change this from ORCL (default Oracle install value) to your SID (if you changed the SID from default upon installation).

  **THREADS**
  The number of concurrent threads. Optional to change.

## Scenarios

### Running Oracle 12c on a local Windows 10 machine, and MSF5 on Ubuntu for Windows (same machine)

```
msf5 auxiliary(scanner/oracle/oracle_hashdump) > show options
Module options (auxiliary/scanner/oracle/oracle_hashdump):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   DBPASS   hunter2          yes       The password to authenticate with.
   DBUSER   scott            yes       The username to authenticate with.
   RHOST    127.0.0.1        yes       The Oracle host.
   RHOSTS   127.0.0.1        yes       The target address range or CIDR identifier
   RPORT    1522             yes       The TNS port.
   SID      staticdb         yes       The sid to authenticate with.
   THREADS  1                yes       The number of concurrent threads

msf5 auxiliary(scanner/oracle/oracle_hashdump) > run

[*] Server is running 12c
[*] Hash table :
 Oracle Server Hashes
====================

 Username               Hash
 --------               ----
 ...
 SCOTT                  S:BF6D4E3791075A348BA76EF533E38F7211513CCE2A3513EE3E3D4A5A4DE0;H:3814C74599475EB73043A1211742EE59;T:0911BAC55EEF63F0C1769E816355BE29492C9D01980DC36C95A86C9CE47F93790631DE3D9A60C90451CFF152E25D9E94F612A1493EC82AF8E3C4D0432B06BA4C2C693B932332BC14D2D66CEF098A4699
 ...
 
[+] Hash Table has been saved
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
These hashes are then saved as credentials so that `jtr_oracle_fast` can crack them (using John The Ripper "bleeding_jumbo" branch via GitHub: https://github.com/magnumripper/JohnTheRipper).

Output of `creds` command:

```
msf5 auxiliary(scanner/oracle/oracle_hashdump) > creds
Credentials
===========

host       origin     service            public  private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----       ------     -------            ------  -------      
...                                                                                                                                                                                                                                                         -----  ------------        ----------
127.0.0.1  127.0.0.1  1522/tcp (oracle)  SCOTT   S:BF6D4E3791075A348BA76EF533E38F7211513CCE2A3513EE3E3D4A5A4DE0;H:3814C74599475EB73043A1211742EE59;T:0911BAC55EEF63F0C1769E816355BE29492C9D01980DC36C95A86C9CE47F93790631DE3D9A60C90451CFF152E25D9E94F612A1493EC82AF8E3C4D0432B06BA4C2C693B932332BC14D2D66CEF098A4699         Nonreplayable hash  oracle12c
...
```

`use auxiliary/analyze/jtr_oracle_fast`

`set JOHN_PATH /path/to/john`

`run`
```
...
[*] Cracking oracle12c hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] SCOTT:hunter2
...
```
