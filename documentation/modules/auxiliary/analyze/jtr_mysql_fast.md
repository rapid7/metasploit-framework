## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode MySQL
  based password hashes, such as:

  * `mysql` (pre 4.1) based passwords
  * `mysql-sha1` based passwords

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `mysql`, or `mysql-sha1` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_mysql_fast```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options


   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking

   **JOHN_PATH**

   The absolute path to the John the Ripper executable.  Default behavior is to search `path` for
   `john` and `john.exe`.

   **KORELOGIC**

   Apply the [KoreLogic rules](http://contest-2010.korelogic.com/rules.html) to Wordlist Mode (slower).
   Default is `false`.

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

   **POT**

   The path to a John POT file (JtR option: `--pot`) to use instead.  The `pot` file is the data file which
   records cracked password hashes.  Kali linux's default location is `/root/.john/john.pot`.
   Default is `~/.msf4/john.pot`.

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

## Scenarios

Create hashes:

```
creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql
creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1
```

Crack them:

```
msf5 > use auxiliary/analyze/jtr_mysql_fast 
msf5 auxiliary(analyze/jtr_mysql_fast) > run

[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-o7pt47
[*] Wordlist file written out to /tmp/jtrtmp20190211-6421-3t366y
[*] Cracking mysql hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking mysql hashes in single mode...
Using default input encoding: UTF-8
[*] Cracking mysql hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] mysql_probe:probe
[*] Cracking mysql-sha1 hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking mysql-sha1 hashes in single mode...
Using default input encoding: UTF-8
[*] Cracking mysql-sha1 hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] mysql-sha1_tere:tere
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_mysql_fast) > creds
Credentials
===========

host  origin  service  public           private                                    realm  private_type        JtR Format
----  ------  -------  ------           -------                                    -----  ------------        ----------
                       mysql_probe      probe                                             Password            
                       mysql_probe      445ff82636a7ba59                                  Nonreplayable hash  mysql
                       mysql-sha1_tere  tere                                              Password            
                       mysql-sha1_tere  *5AD8F88516BD021DD43F171E2C785C69F8E54ADB         Nonreplayable hash  mysql-sha1

```
