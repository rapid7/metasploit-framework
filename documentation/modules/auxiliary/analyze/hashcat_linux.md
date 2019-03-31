## Vulnerable Application

  This module attempts to use [hashcat](https://hashcat.net/hashcat/) to decode Linux
  based password hashes, such as:

  * `DES` based passwords (format 1500)
  * `MD5` based passwords (format 500)
  * `BSDi` based passwords (format 12400)
  * With `crypt` set to `true`:
    * `bf`, `bcrypt`, or `blowfish` based passwords (format 3200)
    * `SHA256` based passwords (format 7400)
    * `SHA512` based passwords (format 1800)

  Sources of hashes can be found here:
  [source](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Verification Steps

  1. Have at least one user with an `des`, `md5`, `bsdi`, `crypt`, `blowfish`, `sha512`, or `sha256` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/hashcat_linux```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options

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

   **HASHCAT_PATH**

   The absolute path to the Hashcat executable.  Default behavior is to search `path` for
   `hashcat` and `hashcat.exe`.

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/hashcat_linux
resource (hashes_hashcat.rb)> set crypt true
crypt => true
resource (hashes_hashcat.rb)> run
[*] Hashes Written out to /tmp/hashes_tmp20190331-15445-1bon488
[*] Wordlist file written out to /tmp/jtrtmp20190331-15445-1es3bt
[*] Cracking md5crypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking md5crypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] md5_password:password
[*] Cracking descrypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking descrypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] des_password:password
[*] Cracking bsdicrypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking bsdicrypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] bsdi_password:password
[*] Cracking sha256crypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking sha256crypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] sha256_password:password
[*] Cracking sha512crypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking sha512crypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] sha512_password:password
[*] Cracking bcrypt hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking bcrypt hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] blowfish_password:password
[*] Auxiliary module execution completed
[*] Starting persistent handler(s)...
msf5 auxiliary(analyze/hashcat_linux) > creds
Credentials
===========

host  origin  service  public             private                                                                                             realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                                             -----  ------------        ----------
                       des_password       password                                                                                                   Password            
                       des_password       rEK1ecacw.7.c                                                                                              Nonreplayable hash  des
                       md5_password       password                                                                                                   Password            
                       md5_password       $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                         Nonreplayable hash  md5
                       bsdi_password      password                                                                                                   Password            
                       bsdi_password      _J9..K0AyUubDrfOgO4s                                                                                       Nonreplayable hash  bsdi
                       sha256_password    password                                                                                                   Password            
                       sha256_password    $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5                                                    Nonreplayable hash  sha256
                       sha512_password    password                                                                                                   Password            
                       sha512_password    $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1         Nonreplayable hash  sha512
                       blowfish_password  password                                                                                                   Password            
                       blowfish_password  $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe                                               Nonreplayable hash  bf

```
