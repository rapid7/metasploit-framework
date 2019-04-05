## Vulnerable Application

  This module attempts to use a password cracker to decode Windows
  based password hashes, such as:

  * `LANMAN` based passwords
  * `NTLM` based passwords

| Common | John     | Hashcat |
|--------|----------|---------|
| lanman | lm       | 3000    |
| ntlm   | nt       | 1000    |

  Sources of hashes can be found here:
  [source](https://openwall.info/wiki/john/sample-hashes), [source2](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

## Verification Steps

  1. Have at least one user with an `ntlm`, or `lanman` password hash in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_windows```
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

   **LANMAN**

   Crack LANMAN hashes.  Default is `true`.

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

   **NTLM**

   Crack NTLM hashes.  Default is `true`.

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

## Scenarios

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
creds add user:lm_password ntlm:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c jtr:lm
creds add user:lm2_password ntlm:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c jtr:lm
creds add user:lm2_pot_password ntlm:e52cac67419fafe2fafe108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c jtr:lm
creds add user:nt_password ntlm:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c jtr:nt
echo "" > /root/.msf4/john.pot
echo "\$LM\$E52CAC67419FAFE2:passwor" >> /root/.msf4/john.pot
echo "\$LM\$FAFE108F3FA6CB6D:d" >> /root/.msf4/john.pot
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
resource (hashes_hashcat.rb)> set action john
action => john
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_windows
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.8.0.13-jumbo-1-bleeding-973a245b96
[*] Hashes Written out to /tmp/hashes_tmp20190520-1036-111i6jd
[*] Wordlist file written out to /tmp/jtrtmp20190520-1036-19ta002
[*] Checking lm hashes already cracked...
[*] Cracking lm hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=4HXsmP3p --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --wordlist=/tmp/jtrtmp20190520-1036-19ta002 --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 4 candidates left, minimum 2048 needed for performance.
1g 0:00:00:00 DONE (2019-05-20 12:43) 100.0g/s 400.0p/s 400.0c/s 1200C/s PASSWOR..TOTO
Warning: passwords printed above might be partial and not be all those cracked
Use the "--show --format=LM" options to display all of the cracked passwords reliably
Session completed
[*] Cracking lm hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=4HXsmP3p --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --wordlist=/tmp/jtrtmp20190520-1036-19ta002 --rules=single --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1059 candidates left, minimum 2048 needed for performance.
1g 0:00:00:00 DONE (2019-05-20 12:43) 50.00g/s 52950p/s 52950c/s 105900C/s PASSWOR..TOTO201
Warning: passwords printed above might be partial and not be all those cracked
Use the "--show --format=LM" options to display all of the cracked passwords reliably
Session completed
[*] Cracking lm hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=4HXsmP3p --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Warning: MaxLen = 20 is too large for the current hash type, reduced to 7
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2019-05-20 12:43) 0g/s 44444Kp/s 44444Kc/s 44444KC/s 0766269..0769743
Session completed
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 479    lm         lm_password       password          Single
 480    lm         lm2_password      password          Single
 481    lm         lm2_pot_password  password          Already Cracked/POT

[*] Checking nt hashes already cracked...
[*] Cracking nt hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=c5i46Zlc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --wordlist=/tmp/jtrtmp20190520-1036-19ta002 --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 4 candidates left, minimum 24 needed for performance.
1g 0:00:00:00 DONE (2019-05-20 12:43) 50.00g/s 200.0p/s 200.0c/s 200.0C/s password..toto
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
[*] Cracking nt hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=c5i46Zlc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --wordlist=/tmp/jtrtmp20190520-1036-19ta002 --rules=single --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
[*] Cracking nt hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=c5i46Zlc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190520-1036-111i6jd
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 479    lm         lm_password       password          Single
 480    lm         lm2_password      password          Single
 481    lm         lm2_pot_password  password          Already Cracked/POT
 482    nt         nt_password       password          Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public            private                                                            realm  private_type  JtR Format
----  ------  -------  ------            -------                                                            -----  ------------  ----------
                       lm_password       e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm2_password      e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm2_pot_password  e52cac67419fafe2fafe108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       nt_password       aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm2_pot_password  password                                                                  Password      
                       lm_password       password                                                                  Password      
                       lm2_password      password                                                                  Password      
                       nt_password       password                                                                  Password      

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
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_windows
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190520-2743-fmvmdf
[*] Wordlist file written out to /tmp/jtrtmp20190520-2743-syi778
[*] Checking lm hashes already cracked...
[*] Cracking lm hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=ZxS82GWy --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3000 --runtime=60 /tmp/hashes_tmp20190520-2743-fmvmdf /tmp/jtrtmp20190520-2743-syi778
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking lm hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=ZxS82GWy --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3000 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190520-2743-fmvmdf
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 497    lm         lm_password   PASSWORD          Wordlist
 498    lm         lm2_password  PASSWORD          Wordlist

[*] Checking nt hashes already cracked...
[*] Cracking nt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=IgHCIWfW --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1000 --runtime=60 /tmp/hashes_tmp20190520-2743-fmvmdf /tmp/jtrtmp20190520-2743-syi778
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking nt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=IgHCIWfW --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1000 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190520-2743-fmvmdf
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 497    lm         lm_password       PASSWORD          Wordlist
 498    lm         lm2_password      PASSWORD          Wordlist
 499    nt         lm2_pot_password  password          Wordlist
 500    nt         nt_password       password          Wordlist

[*] Auxiliary module execution completed
resource (hashes_hashcat.rb)> creds
Credentials
===========

host  origin  service  public            private                                                            realm  private_type  JtR Format
----  ------  -------  ------            -------                                                            -----  ------------  ----------
                       lm_password       e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm2_password      e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm2_pot_password  e52cac67419fafe2fafe108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       nt_password       aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c         NTLM hash     nt,lm
                       lm_password       PASSWORD                                                                  Password      
                       lm2_password      PASSWORD                                                                  Password      
                       lm_password       password                                                                  Password      
                       lm2_password      password                                                                  Password      
                       lm2_pot_password  password                                                                  Password      
                       nt_password       password                                                                  Password      

```
