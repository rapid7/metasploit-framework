## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode oracle
  based password hashes, such as:

  * `oracle` (<=10) aka `des` based passwords
  * `oracle11` based passwords
  * Oracle 11 and 12c backwards compatibility `H` field (MD5)
  * `oracle12c` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

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

Utilizing the `make_hashes` file listed in the Vulnerable Application section:

```
resource (hashes.rb)> use auxiliary/scanner/ssh/ssh_login
resource (hashes.rb)> set username ubuntu
username => ubuntu
resource (hashes.rb)> set password ubuntu
password => ubuntu
resource (hashes.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (hashes.rb)> run
[+] 111.111.1.111:22 - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare) Linux ubuntu1604 4.4.0-138-generic #164-Ubuntu SMP Tue Oct 2 17:16:02 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (2.2.2.2:45369 -> 111.111.1.111:22) at 2019-01-21 15:35:19 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding simon:4F8BC1809CB2AF77:des,oracle
[+] Adding SYSTEM:9EEDFA0AD26C6D52:des,oracle
[+] Adding DEMO:S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C:raw-sha1,oracle
[+] Adding oracle11_epsilon:S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C:raw-sha1,oracle
[+] Adding oracle12c_epsilon:H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B:pbkdf2,oracle12c
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_oracle_fast 
msf5 auxiliary(analyze/jtr_oracle_fast) > run

[*] Wordlist file written out to /tmp/jtrtmp20190121-21358-1qgil9r
[*] Hashes Written out to /tmp/hashes_tmp20190121-21358-1mz3zna
[*] Cracking oracle hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] simon:A
[+] SYSTEM:THALES
[*] Hashes Written out to /tmp/hashes_tmp20190121-21358-1hm4xok
[*] Cracking dynamic_1506 hashes in normal wordlist mode...
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-01-21 15:35) 0g/s 4861Kp/s 9722Kc/s 9722KC/s waneta..vagrant
Session completed
[*] Cracking dynamic_1506 hashes in single mode...
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:14 DONE (2019-01-21 15:36) 0g/s 5680Kp/s 11361Kc/s 11361KC/s ximenes1900..vagrant1900
Session completed
[*] Cracked passwords this run:
[+] DEMO:epsilon
[*] Hashes Written out to /tmp/hashes_tmp20190121-21358-h0fjvl
[*] Cracking oracle11 hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracking oracle11 hashes in single mode...
Using default input encoding: UTF-8
[*] Cracked passwords this run:
[+] DEMO:epsilon
[+] oracle11_epsilon:epsilon
[*] Hashes Written out to /tmp/hashes_tmp20190121-21358-5hgfu5
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

host           origin         service       public              private                                                                                                                                                                                                                                                               realm  private_type
----           ------         -------       ------              -------                                                                                                                                                                                                                                                               -----  ------------
                                            simon               A                                                                                                                                                                                                                                                                            Password
               111.111.1.111                simon               4F8BC1809CB2AF77                                                                                                                                                                                                                                                             Nonreplayable hash
                                            SYSTEM              THALES                                                                                                                                                                                                                                                                       Password
               111.111.1.111                SYSTEM              9EEDFA0AD26C6D52                                                                                                                                                                                                                                                             Nonreplayable hash
                                            DEMO                epsilon                                                                                                                                                                                                                                                                      Password
               111.111.1.111                DEMO                S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash
                                            oracle11_epsilon    epsilon                                                                                                                                                                                                                                                                      Password
               111.111.1.111                oracle11_epsilon    S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash
                                            oracle12c_epsilon   epsilon                                                                                                                                                                                                                                                                      Password
               111.111.1.111                oracle12c_epsilon   H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B                                                                        Nonreplayable hash
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu              ubuntu                                                                                                                                                                                                                                                                       Password
```
