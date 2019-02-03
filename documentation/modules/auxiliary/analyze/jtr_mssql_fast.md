## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode Microsoft
  SQL based password hashes, such as:

  * `mssql` based passwords
  * `mssql05` based passwords
  * `mssql12` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

## Verification Steps

  1. Have at least one user with an `mssql`, `mssql05` or `mssql12` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_mssql_fast```
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
[*] Command shell session 1 opened (2.2.2.2:40997 -> 111.111.1.111:22) at 2019-01-19 16:56:46 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding mssql05_toto:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908:mssql05
[+] Adding mssql_foo:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254:mssql
[+] Adding mssql12_Password1!:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16:mssql12
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_mssql_fast 
msf5 auxiliary(analyze/jtr_mssql_fast) > run

[*] Hashes Written out to /tmp/hashes_tmp20190119-30098-16dm2ip
[*] Wordlist file written out to /tmp/jtrtmp20190119-30098-t4zx7s
[*] Cracking mssql05 hashes in normal wordlist mode...
[*] Cracking mssql05 hashes in single mode...
[*] Cracking mssql05 hashes in incremental mode (Digits)...
[*] Cracked Passwords this run:
[+] mssql05_toto:toto
[+] mssql_foo:foo
[+] mssql05_toto:toto
[+] mssql_foo:foo
[*] Cracking mssql hashes in normal wordlist mode...
[*] Cracking mssql hashes in single mode...
[*] Cracking mssql hashes in incremental mode (Digits)...
[*] Cracked Passwords this run:
[+] mssql_foo:FOO
[+] mssql_foo:FOO
[*] Cracking mssql12 hashes in normal wordlist mode...
[*] Cracking mssql12 hashes in single mode...
[*] Cracking mssql12 hashes in incremental mode (Digits)...
[*] Cracked Passwords this run:
[+] mssql12_Password1!:Password1!
[+] mssql12_Password1!:Password1!
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_mssql_fast) > creds
Credentials
===========

host           origin         service       public              private                                                                                                                                         realm  private_type
----           ------         -------       ------              -------                                                                                                                                         -----  ------------
                                            mssql05_toto        toto                                                                                                                                                   Password
               111.111.1.111                mssql05_toto        0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908                                                                                                 Nonreplayable hash
                                            mssql_foo           FOO                                                                                                                                                    Password
                                            mssql_foo           foo                                                                                                                                                    Password
               111.111.1.111                mssql_foo           0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254                                                         Nonreplayable hash
                                            mssql12_Password1!  Password1!                                                                                                                                             Password
               111.111.1.111                mssql12_Password1!  0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16         Nonreplayable hash
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu              ubuntu                                                                                                                                                 Password

```
