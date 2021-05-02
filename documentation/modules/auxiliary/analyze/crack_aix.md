## Vulnerable Application

  This module attempts to use a password cracker to decode AIX 
  based password hashes, such as:

  * `DES` based passwords

  Formats:

| Common | John     | Hashcat |
|--------| ---------|---------|
| des    | descript | 1500    |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with a `des` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_aix```
  4. Do: set cracker of choice
  5. Do: ```run```
  6. You should hopefully crack a password.

## Actions

   **john**

   Use john the ripper (default).

   **hashcat**

   Use hashcat.

## Options


   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

   **CRACKER_PATH**

   The absolute path to the cracker executable.  Default behavior is to search `path`.

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **Fork**

   This option will set how many forks to use on john the ripper.  Default is `1` (no forking).

   **INCREMENTAL**

   Run the cracker in incremental mode.  Default is `true`

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking

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

   **WORDLIST**

   Run the cracker in dictionary/wordlist mode.  Default is `true`

## Scenarios

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
creds add user:des2_password hash:rEK1ecacw.7.c jtr:des
creds add user:des_password hash:rEK1ecacw.7.c jtr:des
creds add user:des_55 hash:rDpJV6xlcXxRM jtr:des
creds add user:des_pot_55 hash:fakeV6xlcXxRM jtr:des
creds add user:des_passphrase hash:qiyh4XPJGsOZ2MEAyLkfWqeQ jtr:des
echo "fakeV6xlcXxRM:55" >> /root/.msf4/john.pot
echo "test" > /tmp/wordlist
echo "password" >> /tmp/wordlist
```

### John the Ripper

We'll set `ITERATION_TIMEOUT 60` for a quick crack, and `ShowCommand true` for easy debugging.

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_aix
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.9.0-jumbo-1 OMP
[*] Hashes Written out to /tmp/hashes_tmp20190531-27621-1ucwc3l
[*] Wordlist file written out to /tmp/jtrtmp20190531-27621-qk76qr
[*] Checking descrypt hashes already cracked...
[*] Cracking descrypt hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=Z5uRTsvO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=descrypt --wordlist=/tmp/jtrtmp20190531-27621-qk76qr --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-27621-1ucwc3l
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 15:06) 100.0g/s 1103Kp/s 4415Kc/s 4415KC/s test3:::..t1900
Warning: passwords printed above might be partial and not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking descrypt hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=Z5uRTsvO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=descrypt --max-run-time=60 /tmp/hashes_tmp20190531-27621-1ucwc3l
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
3g 0:00:00:00 DONE 1/3 (2019-05-31 15:06) 300.0g/s 614200p/s 614400c/s 614400C/s des_pass..Dde_pass
Warning: passwords printed above might be partial
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking descrypt hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=Z5uRTsvO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=descrypt --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-27621-1ucwc3l
Using default input encoding: UTF-8
[*] Cracking descrypt hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=Z5uRTsvO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=descrypt --wordlist=/tmp/jtrtmp20190531-27621-qk76qr --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-27621-1ucwc3l
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username        Cracked Password  Method
 -----  ---------  --------        ----------------  ------
 1250   descrypt   des2_password   password          Single
 1251   descrypt   des_password    password          Single
 1252   descrypt   des_55          55                Normal
 1253   descrypt   des_pot_55      55                Already Cracked/POT
 1254   descrypt   des_passphrase  passphrase        Normal

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public          private                   realm  private_type        JtR Format
----  ------  -------  ------          -------                   -----  ------------        ----------
                       des2_password   rEK1ecacw.7.c                    Nonreplayable hash  des
                       des_password    rEK1ecacw.7.c                    Nonreplayable hash  des
                       des_55          rDpJV6xlcXxRM                    Nonreplayable hash  des
                       des_pot_55      fakeV6xlcXxRM                    Nonreplayable hash  des
                       des_passphrase  qiyh4XPJGsOZ2MEAyLkfWqeQ         Nonreplayable hash  des
                       des_pot_55      55                               Password            
                       des2_password   password                         Password            
                       des_password    password                         Password            
                       des_55          55                               Password            
                       des_passphrase  passphrase                       Password
```

### Hashcat

We'll set `ITERATION_TIMEOUT 60` for a quick crack, and `ShowCommand true` for easy debugging.

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_aix
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190531-27714-1ct3bn3
[*] Wordlist file written out to /tmp/jtrtmp20190531-27714-1j3q151
[*] Checking descrypt hashes already cracked...
[*] Cracking descrypt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=wCGD0gD0 --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1500 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-27714-1ct3bn3
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking descrypt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=wCGD0gD0 --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1500 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-27714-1ct3bn3 /tmp/jtrtmp20190531-27714-1j3q151
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username       Cracked Password  Method
 -----  ---------  --------       ----------------  ------
 1260   descrypt   des2_password  password          Wordlist
 1261   descrypt   des_password   password          Wordlist
 1262   descrypt   des_55         55                Incremental
 1263   descrypt   des_pot_55     55                Already Cracked/POT

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public          private                   realm  private_type        JtR Format
----  ------  -------  ------          -------                   -----  ------------        ----------
                       des2_password   rEK1ecacw.7.c                    Nonreplayable hash  des
                       des_password    rEK1ecacw.7.c                    Nonreplayable hash  des
                       des_55          rDpJV6xlcXxRM                    Nonreplayable hash  des
                       des_pot_55      fakeV6xlcXxRM                    Nonreplayable hash  des
                       des_passphrase  qiyh4XPJGsOZ2MEAyLkfWqeQ         Nonreplayable hash  des
                       des_pot_55      55                               Password            
                       des_55          55                               Password            
                       des2_password   password                         Password            
                       des_password    password                         Password
```
