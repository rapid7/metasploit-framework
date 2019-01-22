## Vulnerable Application

  This module attempts to use [john the ripper](https://www.openwall.com/john/) to decode Linux
  based password hashes, such as:

  * `DES` based passwords  
  * `MD5` based passwords
  * `BSDi` based passwords
  * With `crypt` set to `true`:
    * `bf`, `bcrypt`, or `blowfish` based passwords
    * `SHA256` based passwords
    * `SHA512` based passwords

  The following can be used to add credentials to the database for cracking:

  * https://github.com/rapid7/metasploit-framework/pull/11264#issuecomment-455762574

  The definition of `crypt` according to JTR and waht algorithms it decodes can be found
  [here](https://github.com/magnumripper/JohnTheRipper/blob/ae24a410baac45bb36884d793c429adeb7197336/src/c3_fmt.c#L731)

## Verification Steps

  1. Have at least one user with an `des`, `md5`, `bsdi`, `crypt`, `blowfish`, `sha512`, or `sha256` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/jtr_linux```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options


   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

   **CRYPT**

   Include `blowfish` and `SHA`(256/512) passwords.

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
[*] Command shell session 1 opened (2.2.2.2:34849 -> 111.111.1.111:22) at 2019-01-19 11:52:44 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (hashes.rb)> use post/test/make_hashes
resource (hashes.rb)> set session 1
session => 1
resource (hashes.rb)> run
[+] Adding des_passphrase:qiyh4XPJGsOZ2MEAyLkfWqeQ:des
[+] Adding des_password:rEK1ecacw.7.c:des
[+] Adding md5_password:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/:md5,des,bsdi,crypt
[+] Adding bsdi_password:_J9..K0AyUubDrfOgO4s:md5,des,bsdi,crypt
[+] Adding crypt_password:SDbsugeBiC58A:md5,des,bsdi,crypt
[+] Adding sha256_password:$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5:md5,des,bsdi,crypt
[+] Adding sha512_password:$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1:md5,des,bsdi,crypt
[+] Adding crypt16_password:qi8H8R7OM4xMUNMPuRAZxlY.:md5,des,bsdi,crypt
[+] Adding blowfish_password:$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe:bcrypt
[*] Post module execution completed
[*] Starting persistent handler(s)...
```
```
msf5 post(test/make_hashes) > use auxiliary/analyze/jtr_linux 
msf5 auxiliary(analyze/jtr_linux) > set crypt true
crypt => true
msf5 auxiliary(analyze/jtr_linux) > run

[*] Hashes Written out to /tmp/hashes_tmp20190119-25843-1igh5zx
[*] Wordlist file written out to /tmp/jtrtmp20190119-25843-1fmcnd
[*] Cracking md5crypt hashes in normal wordlist mode...
[*] Cracked Passwords this run:
[+] md5_password:password
[*] Cracking descrypt hashes in normal wordlist mode...
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (Sat 19 Jan 2019 11:53:04 AM EST) 0g/s 2102Kp/s 6308Kc/s 8411KC/s scapula..vagrant
Session completed
[*] Cracked Passwords this run:
[+] des_passphrase:????????se
[+] des_password:password
[*] Cracking bsdicrypt hashes in normal wordlist mode...
[*] Cracked Passwords this run:
[+] bsdi_password:password
[*] Cracking crypt hashes in normal wordlist mode...
Warning: hash encoding string length 24, type id #3
appears to be unsupported on this system; will not load such hashes.
Warning: hash encoding string length 20, type id #4
appears to be unsupported on this system; will not load such hashes.
Warning: hash encoding string length 60, type id $2
appears to be unsupported on this system; will not load such hashes.
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 59 candidates left, minimum 96 needed for performance.
0g 0:00:00:00 DONE (Sat 19 Jan 2019 11:53:05 AM EST) 0g/s 540061p/s 540061c/s 540061C/s zubeneschamali..vagrant
Session completed
[*] Cracked Passwords this run:
Warning: hash encoding string length 24, type id #3
appears to be unsupported on this system; will not load such hashes.
[+] des_password:password
[+] md5_password:password
[+] sha256_password:password
[+] sha512_password:password
[*] Cracking bcrypt hashes in normal wordlist mode...
[*] Cracked Passwords this run:
[+] blowfish_password:password
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_linux) > creds
Credentials
===========

host           origin         service       public             private                                                                                             realm  private_type
----           ------         -------       ------             -------                                                                                             -----  ------------
                                            des_passphrase     ????????se                                                                                                 Password
               111.111.1.111                des_passphrase     qiyh4XPJGsOZ2MEAyLkfWqeQ                                                                                   Nonreplayable hash
                                            des_password       password                                                                                                   Password
               111.111.1.111                des_password       rEK1ecacw.7.c                                                                                              Nonreplayable hash
                                            md5_password       password                                                                                                   Password
               111.111.1.111                md5_password       $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                         Nonreplayable hash
                                            bsdi_password      password                                                                                                   Password
               111.111.1.111                bsdi_password      _J9..K0AyUubDrfOgO4s                                                                                       Nonreplayable hash
               111.111.1.111                crypt_password     SDbsugeBiC58A                                                                                              Nonreplayable hash
                                            sha256_password    password                                                                                                   Password
               111.111.1.111                sha256_password    $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5                                                    Nonreplayable hash
                                            sha512_password    password                                                                                                   Password
               111.111.1.111                sha512_password    $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1         Nonreplayable hash
               111.111.1.111                crypt16_password   qi8H8R7OM4xMUNMPuRAZxlY.                                                                                   Nonreplayable hash
                                            blowfish_password  password                                                                                                   Password
               111.111.1.111                blowfish_password  $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe                                               Nonreplayable hash
111.111.1.111  111.111.1.111  22/tcp (ssh)  ubuntu             ubuntu                                                                                                     Password
```
