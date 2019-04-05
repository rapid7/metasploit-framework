## Vulnerable Application

  This module attempts to use a password cracker to decode Linux
  based password hashes, such as:

  * `DES` based passwords
  * `MD5` based passwords
  * `BSDi` based passwords
  * `bf`, `bcrypt`, or `blowfish` based passwords
  * `SHA256` based passwords
  * `SHA512` based passwords

| Common   | John        | Hashcat |
|----------|-------------|-------- |
| des      | descript    | 1500    |
| md5      | md5crypt    | 500     |
| bsdi     | bsdicrypt   | 12400   |
| blowfish | bcrypt      | 3200    |
| sha256   | sha256crypt | 7400    |
| sha512   | sha512crypt | 1800    |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `des`, `md5`, `bsdi`, `blowfish`, `sha512`, or `sha256` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_linux```
  4. Do: set cracker of choice
  5. Do: ```run```
  6. You should hopefully crack a password.

## Actions

   **john**

   Use john the ripper (default).

   **hashcat**

   Use hashcat.

## Options

   **BLOWFISH**

   Crack Blowfish hashes. Default is `false`.

   **BSDi**

   Crack BSDi hashes. Default is `true`.

   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`


   **CRACKER_PATH**

   The absolute path to the cracker executable.  Default behavior is to search `path`.

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DES**

   Crack DES hashes. Default is `true`.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **Fork**

   This option will set how many forks to use on john the ripper.  Default is `1` (no forking).

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking.

   **KORELOGIC**

   Apply the [KoreLogic rules](http://contest-2010.korelogic.com/rules.html) to Wordlist Mode (slower).
   Default is `false`.

   **MD5**

   Crack MD5 hashes. Default is `true`.

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

   **SHA256**

   Crack SHA256 hashes. Default is `false`.

   **SHA512**

   Crack SHA12 hashes. Default is `false`.

   **SHOWCOMMAND**

   Show the command being used run from the command line for debugging.  Default is `false`

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

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
echo "" > /root/.msf4/john.pot
echo "fakeV6xlcXxRM:55" >> /root/.msf4/john.pot
echo "\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.fakegHv/:password" >> /root/.msf4/john.pot
echo "test" > /tmp/wordlist
echo "password" >> /tmp/wordlist
echo "toto" >> /tmp/wordlist
creds add user:des2_password hash:rEK1ecacw.7.c jtr:des
creds add user:des_password hash:rEK1ecacw.7.c jtr:des
creds add user:des_55 hash:rDpJV6xlcXxRM jtr:des
creds add user:des_pot_55 hash:fakeV6xlcXxRM jtr:des
creds add user:des_passphrase hash:qiyh4XPJGsOZ2MEAyLkfWqeQ jtr:des
creds add user:md5_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5
creds add user:md52_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5
creds add user:md5_pot_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.fakegHv/ jtr:md5
creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi
creds add user:sha256_password hash:$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256
creds add user:sha512_password hash:$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512
creds add user:blowfish_password hash:$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf
```

### John the Ripper

We'll set `ITERATION_TIMEOUT 60` for a quick crack, `blowfish true`, `sha256 true`, `sha512 true` to handle the bfish, sha256 and sha512 hashes,
and `ShowCommand true` for easy debugging.

```
```

### Hashcat

We'll set `ITERATION_TIMEOUT 60` for a quick crack, `blowfish true`, `sha256 true`, `sha512 true` to handle the bfish, sha256 and sha512 hashes,
and `ShowCommand true` for easy debugging.

```
resource (hashes_hashcat.rb)> setg CUSTOM_WORDLIST /tmp/wordlist
CUSTOM_WORDLIST => /tmp/wordlist
resource (hashes_hashcat.rb)> setg ShowCommand true
ShowCommand => true
resource (hashes_hashcat.rb)> setg USE_DEFAULT_WORDLIST false
USE_DEFAULT_WORDLIST => false
resource (hashes_hashcat.rb)> setg DeleteTempFiles false
DeleteTempFiles => false
resource (hashes_hashcat.rb)> setg USE_CREDS false
USE_CREDS => false
resource (hashes_hashcat.rb)> setg USE_DB_INFO false
USE_DB_INFO => false
resource (hashes_hashcat.rb)> setg USE_HOSTNAMES false
USE_HOSTNAMES => false
resource (hashes_hashcat.rb)> setg USE_ROOT_WORDS false
USE_ROOT_WORDS => false
resource (hashes_hashcat.rb)> setg ITERATION_TIMEOUT 60
ITERATION_TIMEOUT => 60
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_linux
resource (hashes_hashcat.rb)> set blowfish true
blowfish => true
resource (hashes_hashcat.rb)> set sha256 true
sha256 => true
resource (hashes_hashcat.rb)> set sha512 true
sha512 => true
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190519-20242-qlb4hk
[*] Wordlist file written out to /tmp/jtrtmp20190519-20242-11j1u20
[*] Checking md5crypt hashes already cracked...
[*] Cracking md5crypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=a4P056qE --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=500 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking md5crypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=a4P056qE --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=500 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 277    md5crypt   md5_password      password          Wordlist
 278    md5crypt   md52_password     password          Wordlist
 279    md5crypt   md5_pot_password  password          Already Cracked/POT

[*] Checking descrypt hashes already cracked...
[*] Cracking descrypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=8u0Qk6Hb --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1500 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking descrypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=8u0Qk6Hb --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1500 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 272    descrypt   des2_password     password          Wordlist
 273    descrypt   des_password      password          Wordlist
 274    descrypt   des_55            55                Incremental
 275    descrypt   des_pot_55        55                Already Cracked/POT
 277    md5crypt   md5_password      password          Wordlist
 278    md5crypt   md52_password     password          Wordlist
 279    md5crypt   md5_pot_password  password          Already Cracked/POT

[*] Checking bsdicrypt hashes already cracked...
[*] Cracking bsdicrypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=2lpSbSg7 --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12400 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking bsdicrypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=2lpSbSg7 --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12400 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 272    descrypt   des2_password     password          Wordlist
 273    descrypt   des_password      password          Wordlist
 274    descrypt   des_55            55                Incremental
 275    descrypt   des_pot_55        55                Already Cracked/POT
 277    md5crypt   md5_password      password          Wordlist
 278    md5crypt   md52_password     password          Wordlist
 279    md5crypt   md5_pot_password  password          Already Cracked/POT
 280    bsdicrypt  bsdi_password     password          Wordlist

[*] Checking bcrypt hashes already cracked...
[*] Cracking bcrypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=o10YuFIA --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3200 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking bcrypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=o10YuFIA --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3200 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username           Cracked Password  Method
 -----  ---------  --------           ----------------  ------
 272    descrypt   des2_password      password          Wordlist
 273    descrypt   des_password       password          Wordlist
 274    descrypt   des_55             55                Incremental
 275    descrypt   des_pot_55         55                Already Cracked/POT
 277    md5crypt   md5_password       password          Wordlist
 278    md5crypt   md52_password      password          Wordlist
 279    md5crypt   md5_pot_password   password          Already Cracked/POT
 280    bsdicrypt  bsdi_password      password          Wordlist
 283    bcrypt     blowfish_password  password          Wordlist

[*] Checking sha256crypt hashes already cracked...
[*] Cracking sha256crypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=7kJ3WLDf --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=7400 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking sha256crypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=7kJ3WLDf --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=7400 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type    Username           Cracked Password  Method
 -----  ---------    --------           ----------------  ------
 272    descrypt     des2_password      password          Wordlist
 273    descrypt     des_password       password          Wordlist
 274    descrypt     des_55             55                Incremental
 275    descrypt     des_pot_55         55                Already Cracked/POT
 277    md5crypt     md5_password       password          Wordlist
 278    md5crypt     md52_password      password          Wordlist
 279    md5crypt     md5_pot_password   password          Already Cracked/POT
 280    bsdicrypt    bsdi_password      password          Wordlist
 281    sha256crypt  sha256_password    password          Wordlist
 283    bcrypt       blowfish_password  password          Wordlist

[*] Checking sha512crypt hashes already cracked...
[*] Cracking sha512crypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=DkzRimIZ --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1800 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk /tmp/jtrtmp20190519-20242-11j1u20
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking sha512crypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=DkzRimIZ --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1800 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190519-20242-qlb4hk
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type    Username           Cracked Password  Method
 -----  ---------    --------           ----------------  ------
 272    descrypt     des2_password      password          Wordlist
 273    descrypt     des_password       password          Wordlist
 274    descrypt     des_55             55                Incremental
 275    descrypt     des_pot_55         55                Already Cracked/POT
 277    md5crypt     md5_password       password          Wordlist
 278    md5crypt     md52_password      password          Wordlist
 279    md5crypt     md5_pot_password   password          Already Cracked/POT
 280    bsdicrypt    bsdi_password      password          Wordlist
 281    sha256crypt  sha256_password    password          Wordlist
 282    sha512crypt  sha512_password    password          Wordlist
 283    bcrypt       blowfish_password  password          Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public             private                                                                                             realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                                             -----  ------------        ----------
                       des2_password      rEK1ecacw.7.c                                                                                              Nonreplayable hash  des
                       des_password       rEK1ecacw.7.c                                                                                              Nonreplayable hash  des
                       des_55             rDpJV6xlcXxRM                                                                                              Nonreplayable hash  des
                       des_pot_55         fakeV6xlcXxRM                                                                                              Nonreplayable hash  des
                       des_passphrase     qiyh4XPJGsOZ2MEAyLkfWqeQ                                                                                   Nonreplayable hash  des
                       md5_password       $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                         Nonreplayable hash  md5
                       md52_password      $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                         Nonreplayable hash  md5
                       md5_pot_password   $1$O3JMY.Tw$AdLnLjQ/5jXF9.fakegHv/                                                                         Nonreplayable hash  md5
                       bsdi_password      _J9..K0AyUubDrfOgO4s                                                                                       Nonreplayable hash  bsdi
                       sha256_password    $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5                                                    Nonreplayable hash  sha256
                       sha512_password    $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1         Nonreplayable hash  sha512
                       blowfish_password  $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe                                               Nonreplayable hash  bf
                       md5_pot_password   password                                                                                                   Password            
                       md5_password       password                                                                                                   Password            
                       md52_password      password                                                                                                   Password            
                       des_pot_55         55                                                                                                         Password            
                       des2_password      password                                                                                                   Password            
                       des_password       password                                                                                                   Password            
                       des_55             55                                                                                                         Password            
                       bsdi_password      password                                                                                                   Password            
                       blowfish_password  password                                                                                                   Password            
                       sha256_password    password                                                                                                   Password            
                       sha512_password    password                                                                                                   Password            

```
