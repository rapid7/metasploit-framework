## Vulnerable Application

  This module attempts to use a password cracker to decode Mac OS X
  based password hashes, such as:

  * `XSHA` based passwords (10.4-10.6)
  * `XSHA512` based passwords (10.7)
  * `PBKDF2-HMAC-SHA512` based passwords (10.8+)

| Common             | John               | Hashcat |
|--------------------|--------------------|---------|
| xsha               | xsha               | 122     |
| xsha512            | xsha512            | 1722    |
| pbkdf2-hmac-sha512 | pbkdf2-hmac-sha512 | 7100    |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `xsha`, `pbkdf2-hmac-sha512` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_isx```
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

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking.

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

   **PBKDF2-HMAC-SHA512**

   Crack SHA12 hashes. Default is `true`.

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

   **XSHA**

   Crack xsha based hashes. Default is `true`.

## Scenarios

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
creds add user:buddahh hash:7E4F6138BE21EF6A61365A4D3270DAD24A6544EE188ED422 jtr:xsha
creds add user:mama hash:3063D72395EB1A92D9BA9B8C2DF4074A081EDD1954E6B2BA jtr:xsha
creds add user:hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha
creds add user:hashcat hash:$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f9$
echo "" > /root/.msf4/john.pot
echo "3063D72395EB1A92D9BA9B8C2DF4074A081EDD1954E6B2BA:mama" >> /root/.msf4/john.pot
echo "md5be86a79bf20fake2d58d5453c47d4860:password" >> /root/.msf4/john.pot
echo "password" > /tmp/wordlist
echo "buddahh" > /tmp/wordlist
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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_osx
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.9.0-jumbo-1 OMP
[*] Hashes Written out to /tmp/hashes_tmp20190528-14875-ccg4kp
[*] Wordlist file written out to /tmp/jtrtmp20190528-14875-1ck7cu8
[*] Checking xsha hashes already cracked...
[*] Cracking xsha hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=bjlHE8IO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=xsha --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 42 candidates buffered for the current salt, minimum 64 needed for performance.
1g 0:00:00:00 DONE 1/3 (2019-05-28 22:16) 100.0g/s 4200p/s 4200c/s 4200C/s buddahh..buddahha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[*] Cracking xsha hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=bjlHE8IO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=xsha --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
[*] Cracking xsha hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=bjlHE8IO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=xsha --rules=single --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Invalid options combination or duplicate option: "--rules=single"
[*] Cracking xsha hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=bjlHE8IO --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=xsha --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username  Cracked Password  Method
 -----  ---------  --------  ----------------  ------
 702    xsha       buddahh   buddahh           Normal
 703    xsha       mama      mama              Already Cracked/POT

[*] Checking PBKDF2-HMAC-SHA512 hashes already cracked...
[*] Cracking PBKDF2-HMAC-SHA512 hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=TDk73rLG --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA512 --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 12 candidates buffered for the current salt, minimum 32 needed for performance.
1g 0:00:00:00 DONE 1/3 (2019-05-28 22:16) 16.66g/s 200.0p/s 200.0c/s 200.0C/s hashcat..HashcatHashcat
Use the "--show --format=PBKDF2-HMAC-SHA512" options to display all of the cracked passwords reliably
Session completed
[*] Cracking PBKDF2-HMAC-SHA512 hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=TDk73rLG --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA512 --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
[*] Cracking PBKDF2-HMAC-SHA512 hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=TDk73rLG --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA512 --rules=single --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Invalid options combination or duplicate option: "--rules=single"
[*] Cracking PBKDF2-HMAC-SHA512 hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=TDk73rLG --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=PBKDF2-HMAC-SHA512 --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190528-14875-ccg4kp
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type           Username  Cracked Password  Method
 -----  ---------           --------  ----------------  ------
 702    xsha                buddahh   buddahh           Normal
 703    xsha                mama      mama              Already Cracked/POT
 705    PBKDF2-HMAC-SHA512  hashcat   hashcat           Normal

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public   private                                                                                                                                                                                                      realm  private_type        JtR Format
----  ------  -------  ------   -------                                                                                                                                                                                                      -----  ------------        ----------
                       buddahh  7E4F6138BE21EF6A61365A4D3270DAD24A6544EE188ED422                                                                                                                                                                    Nonreplayable hash  xsha
                       mama     3063D72395EB1A92D9BA9B8C2DF4074A081EDD1954E6B2BA                                                                                                                                                                    Nonreplayable hash  xsha
                       hashcat  1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683                                                                                                                                                                    Nonreplayable hash  xsha
                       hashcat  $ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222         Nonreplayable hash  PBKDF2-HMAC-SHA512
                       mama     mama                                                                                                                                                                                                                Password            
                       buddahh  buddahh                                                                                                                                                                                                             Password            
                       hashcat  hashcat                                                                                                                                                                                                             Password            
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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_osx
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190528-14609-1f1q1np
[*] Wordlist file written out to /tmp/jtrtmp20190528-14609-anr5g4
[*] Checking xsha hashes already cracked...
[*] Cracking xsha hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=tYvEjeRn --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=122 --runtime=60 /tmp/hashes_tmp20190528-14609-1f1q1np /tmp/jtrtmp20190528-14609-anr5g4
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking xsha hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=tYvEjeRn --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=122 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190528-14609-1f1q1np
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username  Cracked Password  Method
 -----  ---------  --------  ----------------  ------
 695    xsha       buddahh   buddahh           Wordlist
 696    xsha       mama      mama              Already Cracked/POT
 697    xsha       hashcat   hashcat           Wordlist

[*] Checking PBKDF2-HMAC-SHA512 hashes already cracked...
[*] Cracking PBKDF2-HMAC-SHA512 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=09fIRzES --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=7100 --runtime=60 /tmp/hashes_tmp20190528-14609-1f1q1np /tmp/jtrtmp20190528-14609-anr5g4
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking PBKDF2-HMAC-SHA512 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=09fIRzES --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=7100 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190528-14609-1f1q1np
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type           Username  Cracked Password  Method
 -----  ---------           --------  ----------------  ------
 695    xsha                buddahh   buddahh           Wordlist
 696    xsha                mama      mama              Already Cracked/POT
 697    xsha                hashcat   hashcat           Wordlist
 698    PBKDF2-HMAC-SHA512  hashcat   hashcat           Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public   private                                                                                                                                                                                                      realm  private_type        JtR Format
----  ------  -------  ------   -------                                                                                                                                                                                                      -----  ------------        ----------
                       buddahh  7E4F6138BE21EF6A61365A4D3270DAD24A6544EE188ED422                                                                                                                                                                    Nonreplayable hash  xsha
                       mama     3063D72395EB1A92D9BA9B8C2DF4074A081EDD1954E6B2BA                                                                                                                                                                    Nonreplayable hash  xsha
                       hashcat  1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683                                                                                                                                                                    Nonreplayable hash  xsha
                       hashcat  $ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222         Nonreplayable hash  PBKDF2-HMAC-SHA512
                       mama     mama                                                                                                                                                                                                                Password            
                       hashcat  hashcat                                                                                                                                                                                                             Password            
                       buddahh  buddahh                                                                                                                                                                                                             Password            

```
