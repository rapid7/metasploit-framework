## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode MySQL
  based password hashes, such as:

  * `mysql` (pre 4.1) based passwords
  * `mysql-sha1` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

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

   **ITERATION_TIMOUT**

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
   Default is `metasploit-framework/data/john.pot`.

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
[*] Command shell session 1 opened (2.2.2.2:46211 -> 111.111.1.111:22) at 2019-01-19 17:24:54 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding mysql_probe:445ff82636a7ba59:mysql
[+] Adding mssql-sha1_tere:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB:mysql-sha1
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_mysql_fast 
msf5 auxiliary(analyze/jtr_mysql_fast) > run

[*] Hashes Written out to /tmp/hashes_tmp20190119-30962-19gqf2v
[*] Wordlist file written out to /tmp/jtrtmp20190119-30962-qrof08
[*] Cracking mysql hashes in normal wordlist mode...
[*] Cracking mysql hashes in single mode...
[*] Cracking mysql hashes in incremental mode (Digits)...
[*] Cracked Passwords this run:
[+] mysql_probe:probe
[*] Cracking mysql-sha1 hashes in normal wordlist mode...
[*] Cracking mysql-sha1 hashes in single mode...
[*] Cracking mysql-sha1 hashes in incremental mode (Digits)...
[*] Cracked Passwords this run:
[+] mssql-sha1_tere:tere
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_mysql_fast) > creds
Credentials
===========

host           origin         service       public              private                                                                                                                                         realm  private_type
----           ------         -------       ------              -------                                                                                                                                         -----  ------------
                                            mysql_probe         probe                                                                                                                                                  Password
               111.111.1.111                mysql_probe         445ff82636a7ba59                                                                                                                                       Nonreplayable hash
                                            mssql-sha1_tere     tere                                                                                                                                                   Password
               111.111.1.111                mssql-sha1_tere     *5AD8F88516BD021DD43F171E2C785C69F8E54ADB                                                                                                              Nonreplayable hash
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu              ubuntu                                                                                                                                                 Password
```
