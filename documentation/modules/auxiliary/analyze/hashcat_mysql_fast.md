## Vulnerable Application

  This module attempts to use [hashcat](https://hashcat.net/hashcat/) to decode MySQL
  based password hashes, such as:

  * `mysql` (pre 4.1) based passwords (format 200)
  * `mysql-sha1` based passwords (format 300)

  Sources of hashes can be found here:
  [source](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Verification Steps

  1. Have at least one user with an `mysql`, or `mysql-sha1` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_mysql_fast```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking

   **HASHCAT_PATH**

   The absolute path to the Hashcat executable.  Default behavior is to search `path` for
   `hashcat` and `hashcat.exe`.

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/hashcat_mysql_fast
resource (hashes_hashcat.rb)> run
[*] Hashes Written out to /tmp/hashes_tmp20190331-19376-9zx2yn
[*] Wordlist file written out to /tmp/jtrtmp20190331-19376-1yfgcmv
[*] Cracking mysql hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] mysql_probe:probe
[*] Cracking mysql-sha1 hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mysql-sha1 hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] mysql-sha1_tere:tere
[*] Auxiliary module execution completed
[*] Starting persistent handler(s)...
msf5 auxiliary(analyze/hashcat_mysql_fast) > creds
Credentials
===========

host  origin  service  public           private                                    realm  private_type        JtR Format
----  ------  -------  ------           -------                                    -----  ------------        ----------
                       mysql_probe      probe                                             Password            
                       mysql_probe      445ff82636a7ba59                                  Nonreplayable hash  mysql
                       mysql-sha1_tere  tere                                              Password            
                       mysql-sha1_tere  *5AD8F88516BD021DD43F171E2C785C69F8E54ADB         Nonreplayable hash  mysql-sha1

```
