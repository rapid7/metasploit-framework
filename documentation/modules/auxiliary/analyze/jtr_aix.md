## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode AIX 
  based password hashes, such as:

  * `DES` based passwords

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with a `des` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_aix```
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
creds add user:des_password hash:rEK1ecacw.7.c jtr:des
creds add user:des_passphrase hash:qiyh4XPJGsOZ2MEAyLkfWqeQ jtr:des
```

Crack them:

```
[*] Hashes Written out to /tmp/hashes_tmp20190211-5021-1p3x0lx
[*] Wordlist file written out to /tmp/jtrtmp20190211-5021-66w3u0
[*] Cracking descrypt hashes in normal wordlist mode...
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-02-11 19:29) 0g/s 4206Kp/s 4206Kc/s 4206KC/s scandal..vagrant
Session completed
[*] Cracking descrypt hashes in single mode...
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (2019-02-11 19:29) 0g/s 6681Kp/s 6681Kc/s 6681KC/s qt1902..tude1900
Session completed
[*] Cracking descrypt hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Warning: MaxLen = 20 is too large for the current hash type, reduced to 8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (2019-02-11 19:29) 0g/s 21083Kp/s 21083Kc/s 21083KC/s 73602400..73673952
Session completed
[*] Cracked Passwords this run:
[+] des_password:password
[+] des_passphrase:????????se
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_aix) > creds
Credentials
===========

host  origin  service  public          private                   realm  private_type        JtR Format
----  ------  -------  ------          -------                   -----  ------------        ----------
                       des_passphrase  ????????se                       Password            
                       des_passphrase  qiyh4XPJGsOZ2MEAyLkfWqeQ         Nonreplayable hash  des
                       des_password    rEK1ecacw.7.c                    Nonreplayable hash  des
                       des_password    password                         Password            

```
