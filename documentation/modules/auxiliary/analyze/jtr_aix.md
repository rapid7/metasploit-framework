## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode AIX 
  based password hashes, such as:

  * `DES` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

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
[*] Deleted 3 creds
resource (hashes.rb)> use auxiliary/scanner/ssh/ssh_login
resource (hashes.rb)> set username ubuntu
username => ubuntu
resource (hashes.rb)> set password ubuntu
password => ubuntu
resource (hashes.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (hashes.rb)> run
[+] 111.111.1.111:22 - Success: 'ubuntu:ubuntu' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare) Linux ubuntu1604 4.4.0-138-generic #164-Ubuntu SMP Tue Oct 2 17:16:02 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (2.2.2.2:40085 -> 111.111.1.111:22) at 2019-01-19 04:00:54 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding des_passphrase:qiyh4XPJGsOZ2MEAyLkfWqeQ:des
[+] Adding des_password:rEK1ecacw.7.c:des
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_aix 
msf5 auxiliary(analyze/jtr_aix) > run

[*] Hashes Written out to /tmp/hashes_tmp20190119-17882-1wvuebb
[*] Wordlist file written out to /tmp/jtrtmp20190119-17882-u2m52i
[*] Cracking descrypt hashes in normal wordlist mode...
[*] Loaded 3 password hashes with 3 different salts (descrypt, traditional crypt(3) [DES 256/256 AVX2-16])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[*] password         (des_password)
[*] se               (des_passphrase:2)
2g 0:00:00:00 DONE (Sat 19 Jan 2019 04:01:15 AM EST) 50.00g/s 2111Kp/s 5041Kc/s 5041KC/s sanserif..vagrant
Warning: passwords printed above might be partial
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking descrypt hashes in single mode...
[*] Loaded 3 password hashes with 3 different salts (descrypt, traditional crypt(3) [DES 256/256 AVX2-16])
Will run 8 OpenMP threads
[*] Remaining 1 password hash
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:07 DONE (Sat 19 Jan 2019 04:01:22 AM EST) 0g/s 4867Kp/s 4867Kc/s 4867KC/s hms1902..tude1900
Session completed
[*] Cracking descrypt hashes in incremental mode (Digits)...
[*] Loaded 3 password hashes with 3 different salts (descrypt, traditional crypt(3) [DES 256/256 AVX2-16])
Will run 8 OpenMP threads
[*] Remaining 1 password hash
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (Sat 19 Jan 2019 04:01:28 AM EST) 0g/s 18864Kp/s 18864Kc/s 18864KC/s 73602400..73673952
Session completed
[*] Cracked Passwords this run:
[+] des_passphrase:????????se:3213:
[+] des_password:password:3214:
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_aix) > creds
Credentials
===========

host           origin         service       public          private                   realm  private_type
----           ------         -------       ------          -------                   -----  ------------
               111.111.1.111                des_passphrase  qiyh4XPJGsOZ2MEAyLkfWqeQ         Nonreplayable hash
               111.111.1.111                des_password    rEK1ecacw.7.c                    Nonreplayable hash
                                            des_passphrase  ????????se                       Password
                                            des_password    password                         Password
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu          ubuntu                           Password
```
