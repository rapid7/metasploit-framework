## Vulnerable Application

  This module attempts to use a password cracker to decode varying databases
  based password hashes, such as:

  * `mysql` based passwords
    * `mysql` based passwords
    * `mysql-sha1` based passwords
  * `mssql` based passwords
    * `mssql` based passwords
    * `mssql05` based passwords
    * `mssql12` based passwords
  * `oracle` based passwords
    * `oracle 10` based passwords
    * `oracle 11/12 H values` based passwords
    * `oracle 12c` based passwords
  * `postgres` based passwords


| Common         | John        | Hashcat |
|----------------|-------------|---------|
| mysql          | mysql       | 200     |
| mysql-sha1     | mysql-sha1  | 300     |
| mssql          | mssql       | 131     |
| mssql05        | mssql05     | 132     |
| mssql12        | mssql12     | 1731    |
| oracle 10      | oracle      | n/a     |
| oracle 11/12 H |             | 112     |
| oracle 12c     | sha512crypt | 12300   |
| postgres       | postgres    | 1800    |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with a database password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_databases```
  4. Do: set cracker of choice
  5. Do: ```run```
  6. You should hopefully crack a password.

## Actions

   **john**

   Use john the ripper (default).

   **hashcat**

   Use hashcat.

## Options

   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

   **CRACKER_PATH**

   The absolute path to the cracker executable.  Default behavior is to search `path`.

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **Fork**

   This option will set how many forks to use on john the ripper.  Default is `1` (no forking).

   **INCREMENTAL**

   Run the cracker in incremental mode.  Default is `true`

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking.

   **KORELOGIC**

   Apply the [KoreLogic rules](http://contest-2010.korelogic.com/rules.html) to Wordlist Mode (slower).
   Default is `false`.

   **MSSQL**

   Crack MSSQL hashes. Default is `true`.

   **MYSQL**

   Crack MySQL hashes. Default is `true`.

   **MUTATE**

   Apply common mutations to the Wordlist (SLOW).  Mutations are:

   * `'@' => 'a'`
   * `'0' => 'o'`
   * `'3' => 'e'`
   * `'$' => 's'`
   * `'7' => 't'`
   * `'1' => 'l'`
   * `'5' => 's'`

   Default is `false`.

   **ORACLE**

   Crack oracle hashes. Default is `true`.


   **POSTGRES**

   Crack postgres hashes. Default is `true`.

   **POT**

   The path to a John POT file (JtR option: `--pot`) to use instead.  The `pot` file is the data file which
   records cracked password hashes.  Kali linux's default location is `/root/.john/john.pot`.
   Default is `~/.msf4/john.pot`.

   **SHOWCOMMAND**

   Show the command being used run from the command line for debugging.  Default is `false`

   **USE_CREDS**

   Use existing credential data saved in the database.  Default is `true`.

   **USE_DB_INFO**

   Use looted database schema info to seed the wordlist.  This includes the Database Name, each Table Name,
   and each Column Name.  If the DB is MSSQL, the Instance Name is also used.  Default is `true`.

   **USE_DEFAULT_WORDLIST**

   Use the default metasploit wordlist in `metasploit-framework/data/wordlists/password.lst`.  Default is
   `true`.

   **USE_HOSTNAMES**

   Seed the wordlist with hostnames from the workspace.  Default is `true`.

   **USE_ROOT_WORDS**

   Use the Common Root Words Wordlist in `metasploit-framework/data/wordlists/common_roots.txt`.  Default
   is true.

   **WORDLIST**

   Run the cracker in dictionary/wordlist mode.  Default is `true`

## Scenarios

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05
creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279$
creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E278$
creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql
creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1
## oracle (10) uses usernames in the hashing, so we can't overide that here
creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle
creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle
## oracle 11/12 H value, username is used
creds add user:DEMO hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797$
## oracle 11/12 uses a LONG format, see lib/msf/core/auxiliary/jtr.rb
creds add user:oracle11_epsilon hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:$
creds add user:oracle12c_epsilon hash:'H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B3$
##postgres uses username, so we can't overide that here
creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860
creds add user:example postgres:md5be86a79bf20fake2d58d5453c47d4860
echo "" > /root/.msf4/john.pot
echo "fakeV6xlcXxRM:55" >> /root/.msf4/john.pot
echo "md5be86a79bf20fake2d58d5453c47d4860:password" >> /root/.msf4/john.pot
echo "\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.fakegHv/:password" >> /root/.msf4/john.pot
echo "test" > /tmp/wordlist
echo "password" >> /tmp/wordlist
echo "toto" >> /tmp/wordlist
echo "foo" >> /tmp/wordlist
echo "tere" >> /tmp/wordlist
echo "Password1\!" >> /tmp/wordlist
echo "system" >> /tmp/wordlist
echo "simon" >> /tmp/wordlist
echo "A" >> /tmp/wordlist
echo "THALES" >> /tmp/wordlist
echo "probe" >> /tmp/wordlist
echo "epsilon" >> /tmp/wordlist
echo "t\!" >> /tmp/wordlist
```

### John the Ripper

We'll set `ITERATION_TIMEOUT 60` for a quick crack, and `ShowCommand true` for easy debugging.

```
resource (hashes_hashcat.rb)> setg CUSTOM_WORDLIST /tmp/wordlist
CUSTOM_WORDLIST => /tmp/wordlist
resource (hashes_hashcat.rb)> setg ShowCommand true
ShowCommand => true
resource (hashes_hashcat.rb)> setg USE_DEFAULT_WORDLIST false
USE_DEFAULT_WORDLIST => false
resource (hashes_hashcat.rb)> setg DeleteTempFiles false
DeleteTempFiles => false
resource (hashes_hashcat.rb)> setg USE_CREDS false
USE_CREDS => false
resource (hashes_hashcat.rb)> setg USE_DB_INFO false
USE_DB_INFO => false
resource (hashes_hashcat.rb)> setg USE_HOSTNAMES false
USE_HOSTNAMES => false
resource (hashes_hashcat.rb)> setg USE_ROOT_WORDS false
USE_ROOT_WORDS => false
resource (hashes_hashcat.rb)> setg ITERATION_TIMEOUT 60
ITERATION_TIMEOUT => 60
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_databases
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.9.0-jumbo-1 OMP
[*] Hashes Written out to /tmp/hashes_tmp20190531-29358-125bmsb
[*] Wordlist file written out to /tmp/jtrtmp20190531-29358-11uv1t0
[*] Checking mssql hashes already cracked...
[*] Cracking mssql hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=RiixU30Z --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:44) 50.00g/s 400.0p/s 400.0c/s 400.0C/s TEST3:::..FOO
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mssql hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=RiixU30Z --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=RiixU30Z --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=RiixU30Z --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=RiixU30Z --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username   Cracked Password  Method
 -----  ---------  --------   ----------------  ------
 1357   mssql      mssql_foo  FOO               Single

[*] Checking mssql05 hashes already cracked...
[*] Cracking mssql05 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=3FMqTSQB --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql05 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
2g 0:00:00:00 DONE (2019-05-31 15:44) 100.0g/s 400.0p/s 800.0c/s 800.0C/s test3:::..foo
Use the "--show --format=mssql05" options to display all of the cracked passwords reliably
Session completed
[*] Cracking mssql05 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=3FMqTSQB --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql05 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql05 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=3FMqTSQB --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql05 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql05 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=3FMqTSQB --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql05 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql05 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=3FMqTSQB --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql05 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 1356   mssql05    mssql05_toto  toto              Single
 1357   mssql      mssql_foo     FOO               Single

[*] Checking mssql12 hashes already cracked...
[*] Cracking mssql12 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=Hgkng17W --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql12 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:44) 50.00g/s 409600p/s 409600c/s 409600C/s test3:::..Password1\!99
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mssql12 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=Hgkng17W --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql12 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql12 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=Hgkng17W --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql12 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql12 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=Hgkng17W --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql12 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mssql12 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=Hgkng17W --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mssql12 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username            Cracked Password  Method
 -----  ---------  --------            ----------------  ------
 1356   mssql05    mssql05_toto        toto              Single
 1357   mssql      mssql_foo           FOO               Single
 1358   mssql12    mssql12_Password1!  Password1!        Single

[*] Checking mysql hashes already cracked...
[*] Cracking mysql hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=8zGhJlFs --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:45) 100.0g/s 51200p/s 51200c/s 51200C/s test3:::..est3:::
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mysql hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=8zGhJlFs --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=8zGhJlFs --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=8zGhJlFs --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=8zGhJlFs --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username            Cracked Password  Method
 -----  ---------  --------            ----------------  ------
 1356   mssql05    mssql05_toto        toto              Single
 1357   mssql      mssql_foo           FOO               Single
 1358   mssql12    mssql12_Password1!  Password1!        Single
 1359   mysql      mysql_probe         probe             Single

[*] Checking mysql-sha1 hashes already cracked...
[*] Cracking mysql-sha1 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=nJ1VeTcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql-sha1 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:45) 100.0g/s 1600p/s 1600c/s 1600C/s tere..probe
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mysql-sha1 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=nJ1VeTcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql-sha1 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=nJ1VeTcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql-sha1 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql-sha1 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=nJ1VeTcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql-sha1 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking mysql-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=nJ1VeTcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mysql-sha1 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single

[*] Checking oracle hashes already cracked...
[*] Cracking oracle hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=MEvIkaAE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
2g 0:00:00:00 DONE (2019-05-31 15:45) 66.66g/s 364200p/s 1092Kc/s 1092KC/s TEST3:::..T1900
Use the "--show --format=oracle" options to display all of the cracked passwords reliably
Session completed
[*] Cracking oracle hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=MEvIkaAE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 7 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
Warning: mixed-case charset, but the current hash type is case-insensitive;
some candidate passwords may be unnecessarily tried more than once.
0g 0:00:01:00  3/3 0g/s 2705Kp/s 2705Kc/s 2705KC/s LML489..LST0WO
Session stopped (max run-time reached)
[*] Cracking oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=MEvIkaAE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 7 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
Warning: mixed-case charset, but the current hash type is case-insensitive;
some candidate passwords may be unnecessarily tried more than once.
0g 0:00:01:00  3/3 0g/s 2700Kp/s 2700Kc/s 2700KC/s CKS5ER..CGE0DW
Session stopped (max run-time reached)
[*] Cracking oracle hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=MEvIkaAE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:00  0g/s 2880Kp/s 2880Kc/s 2880KC/s 225486472..229896168
Session stopped (max run-time reached)
[*] Cracking oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=MEvIkaAE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-05-31 15:48) 0g/s 16700p/s 16700c/s 16700C/s TEST3:::..HASHCATING
Session completed
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single
 1361   oracle      simon               A                 Single
 1362   oracle      SYSTEM              THALES            Single

[*] Checking dynamic_1506 hashes already cracked...
[*] Cracking dynamic_1506 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=A4uwmyRE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1506 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1506 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=A4uwmyRE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1506 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1506 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=A4uwmyRE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1506 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1506 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=A4uwmyRE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1506 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1506 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=A4uwmyRE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1506 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single
 1361   oracle      simon               A                 Single
 1362   oracle      SYSTEM              THALES            Single

[*] Checking raw-sha1,oracle hashes already cracked...
Unknown ciphertext format name requested
[*] Cracking raw-sha1,oracle hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=olCLdt27 --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=raw-sha1,oracle --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Unknown ciphertext format name requested
Unknown ciphertext format name requested
[*] Cracking raw-sha1,oracle hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=olCLdt27 --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=raw-sha1,oracle --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Unknown ciphertext format name requested
Unknown ciphertext format name requested
[*] Cracking raw-sha1,oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=olCLdt27 --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=raw-sha1,oracle --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Unknown ciphertext format name requested
Unknown ciphertext format name requested
[*] Cracking raw-sha1,oracle hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=olCLdt27 --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=raw-sha1,oracle --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Unknown ciphertext format name requested
Unknown ciphertext format name requested
[*] Cracking raw-sha1,oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=olCLdt27 --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=raw-sha1,oracle --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Unknown ciphertext format name requested
Unknown ciphertext format name requested
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single
 1361   oracle      simon               A                 Single
 1362   oracle      SYSTEM              THALES            Single

[*] Checking oracle11 hashes already cracked...
[*] Cracking oracle11 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=sYHhhqvp --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle11 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:48) 100.0g/s 2400p/s 2400c/s 2400C/s epsilon..Buddahh
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking oracle11 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=sYHhhqvp --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle11 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle11 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=sYHhhqvp --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle11 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle11 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=sYHhhqvp --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle11 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle11 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=sYHhhqvp --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle11 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single
 1361   oracle      simon               A                 Single
 1362   oracle      SYSTEM              THALES            Single
 1363   oracle11    DEMO                epsilon           Single
 1364   oracle11    oracle11_epsilon    epsilon           Single

[*] Checking oracle12c hashes already cracked...
[*] Cracking oracle12c hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=glBBUtZH --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle12c --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:48) 16.66g/s 2133p/s 2133c/s 2133C/s test3:::..password0
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking oracle12c hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=glBBUtZH --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle12c --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=glBBUtZH --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle12c --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=glBBUtZH --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle12c --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=glBBUtZH --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=oracle12c --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type   Username            Cracked Password  Method
 -----  ---------   --------            ----------------  ------
 1356   mssql05     mssql05_toto        toto              Single
 1357   mssql       mssql_foo           FOO               Single
 1358   mssql12     mssql12_Password1!  Password1!        Single
 1359   mysql       mysql_probe         probe             Single
 1360   mysql-sha1  mysql-sha1_tere     tere              Single
 1361   oracle      simon               A                 Single
 1362   oracle      SYSTEM              THALES            Single
 1363   oracle11    DEMO                epsilon           Single
 1364   oracle11    oracle11_epsilon    epsilon           Single
 1365   oracle12c   oracle12c_epsilon   epsilon           Single

[*] Checking dynamic_1034 hashes already cracked...
[*] Cracking dynamic_1034 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=Ici8lKLE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1034 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:48) 50.00g/s 168000p/s 168000c/s 168000C/s test3:::..:::3tset4
Use the "--show --format=dynamic_1034" options to display all of the cracked passwords reliably
Session completed
[*] Cracking dynamic_1034 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=Ici8lKLE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1034 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1034 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=Ici8lKLE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1034 --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1034 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=Ici8lKLE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1034 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[*] Cracking dynamic_1034 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=Ici8lKLE --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=dynamic_1034 --wordlist=/tmp/jtrtmp20190531-29358-11uv1t0 --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-29358-125bmsb
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type     Username            Cracked Password  Method
 -----  ---------     --------            ----------------  ------
 1356   mssql05       mssql05_toto        toto              Single
 1357   mssql         mssql_foo           FOO               Single
 1358   mssql12       mssql12_Password1!  Password1!        Single
 1359   mysql         mysql_probe         probe             Single
 1360   mysql-sha1    mysql-sha1_tere     tere              Single
 1361   oracle        simon               A                 Single
 1362   oracle        SYSTEM              THALES            Single
 1363   oracle11      DEMO                epsilon           Single
 1364   oracle11      oracle11_epsilon    epsilon           Single
 1365   oracle12c     oracle12c_epsilon   epsilon           Single
 1366   dynamic_1034  example             password          Single

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public              private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----  ------  -------  ------              -------                                                                                                                                                                                                                                                               -----  ------------        ----------
                       mssql_foo           foo                                                                                                                                                                                                                                                                          Password            
                       oracle12c_epsilon   epsilon                                                                                                                                                                                                                                                                      Password            
                       DEMO                epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle11_epsilon    S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       example             md5be86a79bf2043622d58d5453c47d4860                                                                                                                                                                                                                                          Postgres md5        raw-md5,postgres
                       simon               A                                                                                                                                                                                                                                                                            Password            
                       SYSTEM              THALES                                                                                                                                                                                                                                                                       Password            
                       mssql12_Password1!  0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16                                                                                                                               Nonreplayable hash  mssql12
                       mysql-sha1_tere     tere                                                                                                                                                                                                                                                                         Password            
                       mysql_probe         445ff82636a7ba59                                                                                                                                                                                                                                                             Nonreplayable hash  mysql
                       mssql_foo           0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254                                                                                                                                                                               Nonreplayable hash  mssql
                       example             password                                                                                                                                                                                                                                                                     Password            
                       mssql12_Password1!  Password1!                                                                                                                                                                                                                                                                   Password            
                       simon               4F8BC1809CB2AF77                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       mssql05_toto        toto                                                                                                                                                                                                                                                                         Password            
                       oracle11_epsilon    epsilon                                                                                                                                                                                                                                                                      Password            
                       mssql_foo           FOO                                                                                                                                                                                                                                                                          Password            
                       SYSTEM              9EEDFA0AD26C6D52                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       mssql05_toto        0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908                                                                                                                                                                                                                       Nonreplayable hash  mssql05
                       DEMO                S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle12c_epsilon   H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B                                                                        Nonreplayable hash  pbkdf2,oracle12c
                       mysql_probe         probe                                                                                                                                                                                                                                                                        Password            
                       mysql-sha1_tere     *5AD8F88516BD021DD43F171E2C785C69F8E54ADB                                                                                                                                                                                                                                    Nonreplayable hash  mysql-sha1
```

### Hashcat

We'll set `ITERATION_TIMEOUT 60` for a quick crack, and `ShowCommand true` for easy debugging.

```
resource (hashes_hashcat.rb)> setg CUSTOM_WORDLIST /tmp/wordlist
CUSTOM_WORDLIST => /tmp/wordlist
resource (hashes_hashcat.rb)> setg ShowCommand true
ShowCommand => true
resource (hashes_hashcat.rb)> setg USE_DEFAULT_WORDLIST false
USE_DEFAULT_WORDLIST => false
resource (hashes_hashcat.rb)> setg DeleteTempFiles false
DeleteTempFiles => false
resource (hashes_hashcat.rb)> setg USE_CREDS false
USE_CREDS => false
resource (hashes_hashcat.rb)> setg USE_DB_INFO false
USE_DB_INFO => false
resource (hashes_hashcat.rb)> setg USE_HOSTNAMES false
USE_HOSTNAMES => false
resource (hashes_hashcat.rb)> setg USE_ROOT_WORDS false
USE_ROOT_WORDS => false
resource (hashes_hashcat.rb)> setg ITERATION_TIMEOUT 60
ITERATION_TIMEOUT => 60
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_databases
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190531-29687-sp1ejs
[*] Wordlist file written out to /tmp/jtrtmp20190531-29687-1u8mjuq
[*] Checking mssql hashes already cracked...
[*] Cracking mssql hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=dZTr4DsK --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=131 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=dZTr4DsK --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=131 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=dZTr4DsK --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=131 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username   Cracked Password  Method
 -----  ---------  --------   ----------------  ------
 1380   mssql      mssql_foo  FOO               Wordlist

[*] Checking mssql05 hashes already cracked...
[*] Cracking mssql05 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=gKYO7rts --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=132 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql05 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=gKYO7rts --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=132 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql05 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=gKYO7rts --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=132 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 1379   mssql05    mssql05_toto  toto              Wordlist
 1380   mssql      mssql_foo     FOO               Wordlist

[*] Checking mssql12 hashes already cracked...
[*] Cracking mssql12 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=X5k9f6JY --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1731 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql12 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=X5k9f6JY --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1731 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql12 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=X5k9f6JY --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1731 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 1379   mssql05    mssql05_toto  toto              Wordlist
 1380   mssql      mssql_foo     FOO               Wordlist

[*] Checking mysql hashes already cracked...
[*] Cracking mysql hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=L2YwjG1w --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=200 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=L2YwjG1w --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=200 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=L2YwjG1w --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=200 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 1379   mssql05    mssql05_toto  toto              Wordlist
 1380   mssql      mssql_foo     FOO               Wordlist
 1382   mysql      mysql_probe   probe             Wordlist

[*] Checking mysql-sha1 hashes already cracked...
[*] Cracking mysql-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=jMcLuSDn --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=300 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql-sha1 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=jMcLuSDn --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=300 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=jMcLuSDn --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=300 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type   Username         Cracked Password  Method
 -----  ---------   --------         ----------------  ------
 1379   mssql05     mssql05_toto     toto              Wordlist
 1380   mssql       mssql_foo        FOO               Wordlist
 1382   mysql       mysql_probe      probe             Wordlist
 1383   mysql-sha1  mysql-sha1_tere  tere              Wordlist

[*] Checking raw-sha1,oracle hashes already cracked...
[*] Cracking raw-sha1,oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=zd9AkOJu --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking raw-sha1,oracle hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=zd9AkOJu --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking raw-sha1,oracle hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=zd9AkOJu --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type        Username          Cracked Password  Method
 -----  ---------        --------          ----------------  ------
 1379   mssql05          mssql05_toto      toto              Wordlist
 1380   mssql            mssql_foo         FOO               Wordlist
 1382   mysql            mysql_probe       probe             Wordlist
 1383   mysql-sha1       mysql-sha1_tere   tere              Wordlist
 1386   raw-sha1,oracle  DEMO              epsilon           Wordlist
 1387   raw-sha1,oracle  oracle11_epsilon  epsilon           Wordlist

[*] Checking oracle11 hashes already cracked...
[*] Cracking oracle11 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=t5k5I14z --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking oracle11 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=t5k5I14z --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking oracle11 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=t5k5I14z --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=112 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type        Username          Cracked Password  Method
 -----  ---------        --------          ----------------  ------
 1379   mssql05          mssql05_toto      toto              Wordlist
 1380   mssql            mssql_foo         FOO               Wordlist
 1382   mysql            mysql_probe       probe             Wordlist
 1383   mysql-sha1       mysql-sha1_tere   tere              Wordlist
 1386   raw-sha1,oracle  DEMO              epsilon           Wordlist
 1387   raw-sha1,oracle  oracle11_epsilon  epsilon           Wordlist

[*] Checking oracle12c hashes already cracked...
[*] Cracking oracle12c hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=7dadE1Lr --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12300 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking oracle12c hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=7dadE1Lr --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12300 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking oracle12c hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=7dadE1Lr --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12300 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type        Username           Cracked Password  Method
 -----  ---------        --------           ----------------  ------
 1379   mssql05          mssql05_toto       toto              Wordlist
 1380   mssql            mssql_foo          FOO               Wordlist
 1382   mysql            mysql_probe        probe             Wordlist
 1383   mysql-sha1       mysql-sha1_tere    tere              Wordlist
 1386   raw-sha1,oracle  DEMO               epsilon           Wordlist
 1387   raw-sha1,oracle  oracle11_epsilon   epsilon           Wordlist
 1388   oracle12c        oracle12c_epsilon  epsilon           Wordlist

[*] Checking dynamic_1034 hashes already cracked...
[*] Cracking dynamic_1034 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=xtcCnmBc --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/wordlist
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking dynamic_1034 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=xtcCnmBc --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking dynamic_1034 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=xtcCnmBc --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-29687-sp1ejs /tmp/jtrtmp20190531-29687-1u8mjuq
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type        Username           Cracked Password  Method
 -----  ---------        --------           ----------------  ------
 1379   mssql05          mssql05_toto       toto              Wordlist
 1380   mssql            mssql_foo          FOO               Wordlist
 1382   mysql            mysql_probe        probe             Wordlist
 1383   mysql-sha1       mysql-sha1_tere    tere              Wordlist
 1386   raw-sha1,oracle  DEMO               epsilon           Wordlist
 1387   raw-sha1,oracle  oracle11_epsilon   epsilon           Wordlist
 1388   oracle12c        oracle12c_epsilon  epsilon           Wordlist
 1389   dynamic_1034     example            password          Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public              private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----  ------  -------  ------              -------                                                                                                                                                                                                                                                               -----  ------------        ----------
                       mssql05_toto        0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908                                                                                                                                                                                                                       Nonreplayable hash  mssql05
                       mssql_foo           0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254                                                                                                                                                                               Nonreplayable hash  mssql
                       mssql12_Password1!  0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16                                                                                                                               Nonreplayable hash  mssql12
                       mysql_probe         445ff82636a7ba59                                                                                                                                                                                                                                                             Nonreplayable hash  mysql
                       mysql-sha1_tere     *5AD8F88516BD021DD43F171E2C785C69F8E54ADB                                                                                                                                                                                                                                    Nonreplayable hash  mysql-sha1
                       simon               4F8BC1809CB2AF77                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       SYSTEM              9EEDFA0AD26C6D52                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       DEMO                S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle11_epsilon    S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle12c_epsilon   H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B                                                                        Nonreplayable hash  pbkdf2,oracle12c
                       example             md5be86a79bf2043622d58d5453c47d4860                                                                                                                                                                                                                                          Postgres md5        raw-md5,postgres
                       mssql_foo           FOO                                                                                                                                                                                                                                                                          Password            
                       mssql05_toto        toto                                                                                                                                                                                                                                                                         Password            
                       mysql_probe         probe                                                                                                                                                                                                                                                                        Password            
                       mysql-sha1_tere     tere                                                                                                                                                                                                                                                                         Password            
                       oracle11_epsilon    epsilon                                                                                                                                                                                                                                                                      Password            
                       DEMO                epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle12c_epsilon   epsilon                                                                                                                                                                                                                                                                      Password            
                       example             password                                                                                                                                                                                                                                                                     Password
```
