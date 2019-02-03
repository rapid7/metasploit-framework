## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode Windows
  based password hashes, such as:

  * `LM`, or `LANMAN` based passwords
  * `NT`, `NTLM`, or `NTLANMAN` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

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
[*] Command shell session 1 opened (2.2.2.2:38243 -> 111.111.1.111:22) at 2019-01-19 05:28:14 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding lm_password:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C:lm
[+] Adding lm_passphrase:855C3697D9979E78AC404C4BA2C66533:7F8FE03093CC84B267B109625F6BBF4B:lm
[+] Adding nt_password:00000000000000000000000000000000:8846F7EAEE8FB117AD06BDD830B7586C:nt
[+] Adding nt_passphrase:00000000000000000000000000000000:7F8FE03093CC84B267B109625F6BBF4B:nt
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_windows_fast 
msf5 auxiliary(analyze/jtr_windows_fast) > run

[*] Hashes Written out to /tmp/hashes_tmp20190123-2730-1wr8x6o
[*] Wordlist file written out to /tmp/jtrtmp20190123-2730-lx6cxy
[*] Cracking lm hashes in normal wordlist mode...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-01-23 16:00) 0g/s 2573Kp/s 2573Kc/s 2573KC/s STEEPER..VAGRANT
Session completed
[*] Cracking lm hashes in single mode...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 DONE (2019-01-23 16:01) 0g/s 5927Kp/s 5927Kc/s 5927KC/s HAS1907..E1900
Session completed
[*] Cracking lm hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Warning: MaxLen = 20 is too large for the current hash type, reduced to 7
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-01-23 16:01) 0g/s 39682Kp/s 39682Kc/s 39682KC/s 0766269..0769743
Session completed
[*] Cracked Passwords this run:
[+] lm_password:password
[+] lm_passphrase:passphrase
[*] Cracking nt hashes in normal wordlist mode...
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-01-23 16:01) 0g/s 3836Kp/s 3836Kc/s 3836KC/s yardarm..yipped
Session completed
[*] Cracking nt hashes in single mode...
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2019-01-23 16:01) 0g/s 15131Kp/s 15131Kc/s 15131KC/s yankee1900..yipped1900
Session completed
[*] Cracking nt hashes in incremental mode (Digits)...
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 DONE (2019-01-23 16:01) 0g/s 40700Kp/s 40700Kc/s 40700KC/s 73673897..73673952
Session completed
[*] Cracked Passwords this run:
[+] lm_password:password
[+] nt_password:password
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_windows_fast) > creds
Credentials
===========

host           origin         service       public          private                                                            realm  private_type
----           ------         -------       ------          -------                                                            -----  ------------
                                            lm_password     password                                                                  Password
               111.111.1.111                lm_password     e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash
                                            lm_passphrase   passphrase                                                                Password
               111.111.1.111                lm_passphrase   855c3697d9979e78ac404c4ba2c66533:7f8fe03093cc84b267b109625f6bbf4b         NTLM hash
                                            nt_password     password                                                                  Password
               111.111.1.111                nt_password     00000000000000000000000000000000:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash
               111.111.1.111                nt_passphrase   00000000000000000000000000000000:7f8fe03093cc84b267b109625f6bbf4b         NTLM hash
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu          ubuntu                                                                    Password

```
