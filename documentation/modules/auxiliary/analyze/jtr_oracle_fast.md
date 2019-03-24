## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode oracle
  based password hashes, such as:

  * `oracle` (<=10) aka `des` based passwords
  * `oracle11` based passwords
  * Oracle 11 and 12c backwards compatibility `H` field (MD5)
  * `oracle12c` based passwords

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

  For a detailed explanation of Oracle 11/12c formats, see
  [www.trustwave.com](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/changes-in-oracle-database-12c-password-hashes/).

  Oracle 11/12c `H` field is `dynamic_1506` in JtR and added
  [here](https://github.com/magnumripper/JohnTheRipper/commit/53973c5e6eb026ea232ba643f9aa20a1ffee0ffb)

## Verification Steps

  1. Have at least one user with an `oracle`, `oracle11`, or `oracle12c` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_oracle_fast```
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
creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle
creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle
creds add user:DEMO hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
creds add user:oracle11_epsilon hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
creds add user:oracle12c_epsilon hash:'H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B' jtr:pbkdf2,oracle12c
```

Crack them:

```
msf5 > use auxiliary/analyze/jtr_oracle_fast 
msf5 auxiliary(analyze/jtr_oracle_fast) > run

[*] Wordlist file written out to /tmp/jtrtmp20190211-6421-v6a8wg
[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-123367o
[*] Cracking oracle hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] simon:A
[+] SYSTEM:THALES
[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-1skc10b
[*] Cracking dynamic_1506 hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking dynamic_1506 hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-1qwsyoy
[*] Cracking oracle11 hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle11 hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] DEMO:epsilon
[+] oracle11_epsilon:epsilon
[*] Hashes Written out to /tmp/hashes_tmp20190211-6421-1f9piv4
[*] Cracking oracle12c hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle12c hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] oracle12c_epsilon:epsilon
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_oracle_fast) > creds
Credentials
===========

host  origin  service  public             private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                                                                                                                                                                                                               -----  ------------        ----------
                       simon              A                                                                                                                                                                                                                                                                            Password            
                       simon              4F8BC1809CB2AF77                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       SYSTEM             THALES                                                                                                                                                                                                                                                                       Password            
                       SYSTEM             9EEDFA0AD26C6D52                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       DEMO               epsilon                                                                                                                                                                                                                                                                      Password            
                       DEMO               S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle11_epsilon   epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle11_epsilon   S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle12c_epsilon  epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle12c_epsilon  H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B                                                                        Nonreplayable hash  pbkdf2,oracle12c

```
