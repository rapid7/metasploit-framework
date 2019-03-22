## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode Windows
  based password hashes, such as:

  * `LM`, or `LANMAN` based passwords
  * `NT`, `NTLM`, or `NTLANMAN` based passwords

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `nt` or `lm` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_windows_fast```
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
creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm
creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt
```

Crack them:

```
msf5 > use auxiliary/analyze/jtr_windows_fast 
msf5 auxiliary(analyze/jtr_windows_fast) > run

[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-koittz
[*] Wordlist file written out to /tmp/jtrtmp20190211-6421-1v82lkm
[*] Cracking lm hashes in normal wordlist mode...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-02-11 19:34) 0g/s 1177Kp/s 1177Kc/s 1177KC/s PLANO..VAGRANT
Session completed
[*] Cracking lm hashes in single mode...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 DONE (2019-02-11 19:34) 0g/s 4634Kp/s 4634Kc/s 4634KC/s WAC1907..E1900
Session completed
[*] Cracking lm hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-02-11 19:34) 0g/s 41152Kp/s 41152Kc/s 41152KC/s 0766269..0769743
Session completed
[*] Cracked Passwords this run:
[+] lm_password:password
[*] Cracking nt hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking nt hashes in single mode...
Using default input encoding: UTF-8
[*] Cracking nt hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] lm_password:password
[+] nt_password:password
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_windows_fast) > creds
Credentials
===========

host  origin  service  public       private                                                            realm  private_type  JtR Format
----  ------  -------  ------       -------                                                            -----  ------------  ----------
                       lm_password  password                                                                  Password      
                       lm_password  e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       nt_password  password                                                                  Password      
                       nt_password  aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm

```
