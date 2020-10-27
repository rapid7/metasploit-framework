## Vulnerable Application

  This module attempts to use a password cracker to decode Webapps
  based password hashes, such as:

  * `atlassian` based passwords
  * `phpass` based passwords (wordpress, joomla, phpBB3)
  * `mediawiki` based passwords

| Common    | John             | Hashcat |
|-----------|------------------|-------- |
| atlassian | PBKDF2-HMAC-SHA1 | 12001   |
| mediawiki | mediawiki        | 3711    |
| phpass    | phpass           | 400     |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `atlassian`, `mediawiki`, or `phpass` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_webapps```
  4. Do: set cracker of choice
  5. Do: ```run```
  6. You should hopefully crack a password.

## Actions

   **john**

   Use john the ripper (default).

   **hashcat**

   Use hashcat.

## Options

   **ATLASSIAN**

   Crack atlassian hashes. Default is `true`.

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

   The max-run-time for each iteration of cracking.

   **KORELOGIC**

   Apply the [KoreLogic rules](http://contest-2010.korelogic.com/rules.html) to Wordlist Mode (slower).
   Default is `false`.

   **MEDIAWIKI**

   Crack mediawiki hashes. Default is `true`.

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

   **PHPASS**

   Crack PHPASS hashes. Default is `true`.

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
echo "" > /root/.msf4/john.pot
echo "fakeV6xlcXxRM:55" >> /root/.msf4/john.pot
echo "\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.fakegHv/:password" >> /root/.msf4/john.pot
echo "test" > /tmp/wordlist
echo "password" >> /tmp/wordlist
echo "toto" >> /tmp/wordlist
echo "hashcat" >> /tmp/wordlist
creds add user:mediawiki_qwerty hash:$B$113$de2874e33da25313d808d2a8cbf31485 jtr:mediawiki
creds add user:mediawiki_hashcat hash:$B$56668501$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki
creds add user:phpass_p_hashcat hash:$P$984478476IagS59wHZvyQMArzfx58u. jtr:phpass
creds add user:phpass_h_hashcat hash:$H$984478476IagS59wHZvyQMArzfx58u. jtr:phpass
creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1
creds add user:atlassian_secret hash:{PKCS5S2}/eWKocWoBMiEN6aA2SQMm56/qLdCVW0fmGF4zF3CzeyaoZUpW1tE3R/fxnYjGbza jtr:PBKDF2-HMAC-SHA1
creds add user:atlassian_admin hash:{PKCS5S2}8WEZjkCbLWysbcbZ5PRgMbdJgJOhkzRT3y1jxOqke2z1Zr79q8ypugFQEYaMoIZt jtr:PBKDF2-HMAC-SHA1
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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_webapps
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.9.0-jumbo-1 OMP
[*] Hashes Written out to /tmp/hashes_tmp20190531-3775-yc870y
[*] Wordlist file written out to /tmp/jtrtmp20190531-3775-5tikjk
[*] Checking PBKDF2-HMAC-SHA1 hashes already cracked...
[*] Cracking PBKDF2-HMAC-SHA1 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=UEKq1EAc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA1 --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:03 DONE (2019-05-31 18:59) 0.2564g/s 4375p/s 8883c/s 8883C/s password11908..t1900
Use the "--show --format=PBKDF2-HMAC-SHA1" options to display all of the cracked passwords reliably
Session completed
[*] Cracking PBKDF2-HMAC-SHA1 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=UEKq1EAc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA1 --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
2g 0:00:00:00 DONE 1/3 (2019-05-31 18:59) 50.00g/s 3175p/s 3200c/s 3200C/s atlassian_admin..Atlassianatlassian
Use the "--show --format=PBKDF2-HMAC-SHA1" options to display all of the cracked passwords reliably
Session completed
[*] Cracking PBKDF2-HMAC-SHA1 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=UEKq1EAc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA1 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[*] Cracking PBKDF2-HMAC-SHA1 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=UEKq1EAc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA1 --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1535   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Single
 1536   PBKDF2-HMAC-SHA1  atlassian_secret   secret            Normal
 1537   PBKDF2-HMAC-SHA1  atlassian_admin    admin             Normal

[*] Checking phpass hashes already cracked...
[*] Cracking phpass hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=ELA5O5SC --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=phpass --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
2g 0:00:00:00 DONE (2019-05-31 18:59) 100.0g/s 38400p/s 38400c/s 76800C/s test3:::..tere9
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
[*] Cracking phpass hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=ELA5O5SC --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=phpass --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE 1/3 (2019-05-31 18:59) 100.0g/s 19200p/s 19200c/s 19200C/s phpass_p_hashcat..tachsah_p_ssaphptachsaH
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
[*] Cracking phpass hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=ELA5O5SC --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=phpass --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[*] Cracking phpass hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=ELA5O5SC --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=phpass --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1533   phpass            phpass_p_hashcat   hashcat           Normal
 1534   phpass            phpass_h_hashcat   hashcat           Single
 1535   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Single
 1536   PBKDF2-HMAC-SHA1  atlassian_secret   secret            Normal
 1537   PBKDF2-HMAC-SHA1  atlassian_admin    admin             Normal

[*] Checking mediawiki hashes already cracked...
[*] Cracking mediawiki hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=D6d9Rjcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mediawiki --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 18:59) 50.00g/s 853300p/s 1021Kc/s 1021KC/s thales1913..t1900
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mediawiki hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=D6d9Rjcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mediawiki --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE 1/3 (2019-05-31 18:59) 100.0g/s 4800p/s 4800c/s 4800C/s mediawiki_qwerty..mediawikimediawiki_qwertymediawikimediawiki_qwerty
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking mediawiki hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=D6d9Rjcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mediawiki --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[*] Cracking mediawiki hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=D6d9Rjcl --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=mediawiki --wordlist=/tmp/jtrtmp20190531-3775-5tikjk --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-3775-yc870y
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1531   mediawiki         mediawiki_qwerty   qwerty            Normal
 1532   mediawiki         mediawiki_hashcat  hashcat           Single
 1533   phpass            phpass_p_hashcat   hashcat           Normal
 1534   phpass            phpass_h_hashcat   hashcat           Single
 1535   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Single
 1536   PBKDF2-HMAC-SHA1  atlassian_secret   secret            Normal
 1537   PBKDF2-HMAC-SHA1  atlassian_admin    admin             Normal

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public             private                                                                    realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                    -----  ------------        ----------
                       mediawiki_hashcat  hashcat                                                                           Password            
                       phpass_p_hashcat   hashcat                                                                           Password            
                       phpass_h_hashcat   hashcat                                                                           Password            
                       atlassian_hashcat  hashcat                                                                           Password            
                       mediawiki_qwerty   $B$113$de2874e33da25313d808d2a8cbf31485                                           Nonreplayable hash  mediawiki
                       mediawiki_hashcat  $B$56668501$0ce106caa70af57fd525aeaf80ef2898                                      Nonreplayable hash  mediawiki
                       phpass_p_hashcat   $P$984478476IagS59wHZvyQMArzfx58u.                                                Nonreplayable hash  phpass
                       phpass_h_hashcat   $H$984478476IagS59wHZvyQMArzfx58u.                                                Nonreplayable hash  phpass
                       atlassian_hashcat  {PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       atlassian_secret   {PKCS5S2}/eWKocWoBMiEN6aA2SQMm56/qLdCVW0fmGF4zF3CzeyaoZUpW1tE3R/fxnYjGbza         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       atlassian_admin    {PKCS5S2}8WEZjkCbLWysbcbZ5PRgMbdJgJOhkzRT3y1jxOqke2z1Zr79q8ypugFQEYaMoIZt         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       atlassian_secret   secret                                                                            Password            
                       atlassian_admin    admin                                                                             Password            
                       mediawiki_qwerty   qwerty                                                                            Password
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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_webapps
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190531-3903-kn244m
[*] Wordlist file written out to /tmp/jtrtmp20190531-3903-r8ligw
[*] Checking PBKDF2-HMAC-SHA1 hashes already cracked...
[*] Cracking PBKDF2-HMAC-SHA1 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=hWnnDYym --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12001 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking PBKDF2-HMAC-SHA1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=hWnnDYym --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=12001 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m /tmp/jtrtmp20190531-3903-r8ligw
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1549   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Wordlist

[*] Checking phpass hashes already cracked...
[*] Cracking phpass hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=dZ7kuaal --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=400 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking phpass hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=dZ7kuaal --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=400 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m /tmp/jtrtmp20190531-3903-r8ligw
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1547   phpass            phpass_p_hashcat   hashcat           Wordlist
 1549   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Wordlist

[*] Checking mediawiki hashes already cracked...
[*] Cracking mediawiki hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=nasHCHQx --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3711 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mediawiki hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=nasHCHQx --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3711 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-3903-kn244m /tmp/jtrtmp20190531-3903-r8ligw
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type         Username           Cracked Password  Method
 -----  ---------         --------           ----------------  ------
 1546   mediawiki         mediawiki_hashcat  hashcat           Wordlist
 1547   phpass            phpass_p_hashcat   hashcat           Wordlist
 1549   PBKDF2-HMAC-SHA1  atlassian_hashcat  hashcat           Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public             private                                                                    realm  private_type        JtR Format
----  ------  -------  ------             -------                                                                    -----  ------------        ----------
                       phpass_h_hashcat   $H$984478476IagS59wHZvyQMArzfx58u.                                                Nonreplayable hash  phpass
                       mediawiki_qwerty   $B$113$de2874e33da25313d808d2a8cbf31485                                           Nonreplayable hash  mediawiki
                       mediawiki_hashcat  $B$56668501$0ce106caa70af57fd525aeaf80ef2898                                      Nonreplayable hash  mediawiki
                       mediawiki_hashcat  hashcat                                                                           Password            
                       atlassian_admin    {PKCS5S2}8WEZjkCbLWysbcbZ5PRgMbdJgJOhkzRT3y1jxOqke2z1Zr79q8ypugFQEYaMoIZt         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       phpass_p_hashcat   hashcat                                                                           Password            
                       atlassian_hashcat  hashcat                                                                           Password            
                       atlassian_hashcat  {PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       atlassian_secret   {PKCS5S2}/eWKocWoBMiEN6aA2SQMm56/qLdCVW0fmGF4zF3CzeyaoZUpW1tE3R/fxnYjGbza         Nonreplayable hash  PBKDF2-HMAC-SHA1
                       phpass_p_hashcat   $P$984478476IagS59wHZvyQMArzfx58u.                                                Nonreplayable hash  phpass
```
