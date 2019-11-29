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

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

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

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

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

Create hashes:

```
creds add user:des_password hash:rEK1ecacw.7.c jtr:des
creds add user:md5_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5
creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi
creds add user:sha256_password hash:$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt
creds add user:sha512_password hash:$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt
creds add user:blowfish_password hash:$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf
```

Crack them:

```
msf5 > use auxiliary/analyze/jtr_linux 
msf5 auxiliary(analyze/jtr_linux) > set crypt true
crypt => true
msf5 auxiliary(analyze/jtr_linux) > run

[*] Hashes Written out to /tmp/hashes_tmp20190211-5021-hqwf2h
[*] Wordlist file written out to /tmp/jtrtmp20190211-5021-1ixz59k
[*] Cracking md5crypt hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] md5_password:password
[*] Cracking descrypt hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] des_password:password
[*] Cracking bsdicrypt hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] bsdi_password:password
[*] Cracking crypt hashes in normal wordlist mode...
Warning: hash encoding string length 20, type id #4
appears to be unsupported on this system; will not load such hashes.
Warning: hash encoding string length 60, type id $2
appears to be unsupported on this system; will not load such hashes.
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] des_password:password
[+] md5_password:password
[+] sha256_password:password
[+] sha512_password:password
[*] Cracking bcrypt hashes in normal wordlist mode...
Using default input encoding: UTF-8
[*] Cracked Passwords this run:
[+] blowfish_password:password
[*] Auxiliary module execution completed
msf5 auxiliary(analyze/jtr_linux) > creds
Credentials
===========

host  origin  service  public             private                                                                                             realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                                             -----  ------------        ----------
                       bsdi_password      password                                                                                                   Password            
                       des_password       password                                                                                                   Password            
                       sha256_password    $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5                                                    Nonreplayable hash  sha256,crypt
                       md5_password       password                                                                                                   Password            
                       md5_password       $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                         Nonreplayable hash  md5
                       bsdi_password      _J9..K0AyUubDrfOgO4s                                                                                       Nonreplayable hash  bsdi
                       sha512_password    password                                                                                                   Password            
                       blowfish_password  $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe                                               Nonreplayable hash  bf
                       sha512_password    $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1         Nonreplayable hash  sha512,crypt
                       sha256_password    password                                                                                                   Password            
                       des_password       rEK1ecacw.7.c                                                                                              Nonreplayable hash  des
                       blowfish_password  password                                                                                                   Password            

```
