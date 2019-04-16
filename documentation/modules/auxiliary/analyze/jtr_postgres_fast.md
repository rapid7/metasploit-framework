## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode PostgreSQL
  based password hashes, such as:

  * `postgres` based passwords
  * `raw-md5` based passwords

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

  PostgreSQL is a `raw-md5` format with the username appended to the password.  This format was
  added to JtR as `dynamic_1034` [here](https://github.com/magnumripper/JohnTheRipper/commit/e57d740bed5c4f4e40a0ff346bcdde270a8173e6)

## Verification Steps

  1. Have at least one user with an `postgres`, or `raw-md5` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_postgres_fast```
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
creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860
```

Crack them:

```
msf5 > use auxiliary/analyze/jtr_postgres_fast 
msf5 auxiliary(analyze/jtr_postgres_fast) > run

[*] Hashes written out to /tmp/hashes_tmp20190211-6421-1hooxft
[*] Wordlist file written out to /tmp/jtrtmp20190211-6421-1hv6clq
[*] Cracking dynamic_1034 hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking dynamic_1034 hashes in single mode...
Using default input encoding: UTF-8
[*] Cracking dynamic_1034 hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] example:password
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_postgres_fast) > creds
Credentials
===========

host  origin  service  public   private                              realm  private_type  JtR Format
----  ------  -------  ------   -------                              -----  ------------  ----------
                       example  md5be86a79bf2043622d58d5453c47d4860         Postgres md5  raw-md5,postgres
                       example  password                                    Password      

```
