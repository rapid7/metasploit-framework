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

   **INCREMENTAL**

   Run the cracker in incremental mode.  Default is `true`

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

   **WORDLIST**

   Run the cracker in dictionary/wordlist mode.  Default is `true`

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_windows
resource (hashes_hashcat.rb)> run
[+] john Version Detected: 1.9.0-jumbo-1 OMP
[*] Hashes Written out to /tmp/hashes_tmp20190531-32530-1bqr8cd
[*] Wordlist file written out to /tmp/jtrtmp20190531-32530-1qjwpit
[*] Checking lm hashes already cracked...
[*] Cracking lm hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=sFX9A0yc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --wordlist=/tmp/jtrtmp20190531-32530-1qjwpit --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
2g 0:00:00:00 DONE (2019-05-31 17:07) 200.0g/s 585500p/s 585500c/s 1756KC/s TEST3::..T1900
Warning: passwords printed above might be partial and not be all those cracked
Use the "--show --format=LM" options to display all of the cracked passwords reliably
Session completed
[*] Cracking lm hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=sFX9A0yc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
Using default target encoding: CP850
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 336 candidates buffered for the current salt, minimum 2048 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
1g 0:00:00:00 DONE 2/3 (2019-05-31 17:07) 50.00g/s 1774Kp/s 1774Kc/s 1774KC/s 123456..SEEKER0
Warning: passwords printed above might be partial
Use the "--show --format=LM" options to display all of the cracked passwords reliably
Session completed
[*] Cracking lm hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=sFX9A0yc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
Using default target encoding: CP850
[*] Cracking lm hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=sFX9A0yc --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=lm --wordlist=/tmp/jtrtmp20190531-32530-1qjwpit --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
Using default target encoding: CP850
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 1462   lm         lm_password       password          Single
 1463   lm         lm2_password      password          Single
 1464   lm         lm2_pot_password  password          Already Cracked/POT

[*] Checking nt hashes already cracked...
[*] Cracking nt hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=MUVWOAMV --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --wordlist=/tmp/jtrtmp20190531-32530-1qjwpit --rules=single --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:00 DONE (2019-05-31 17:07) 100.0g/s 19200p/s 19200c/s 19200C/s test3:::..Password12
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
[*] Cracking nt hashes in normal mode
[*]    Cracking Command: /usr/sbin/john --session=MUVWOAMV --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
[*] Cracking nt hashes in incremental mode...
[*]    Cracking Command: /usr/sbin/john --session=MUVWOAMV --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --incremental=Digits --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
[*] Cracking nt hashes in wordlist mode...
[*]    Cracking Command: /usr/sbin/john --session=MUVWOAMV --nolog --config=/root/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=nt --wordlist=/tmp/jtrtmp20190531-32530-1qjwpit --rules=wordlist --max-run-time=60 /tmp/hashes_tmp20190531-32530-1bqr8cd
Using default input encoding: UTF-8
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 1462   lm         lm_password       password          Single
 1463   lm         lm2_password      password          Single
 1464   lm         lm2_pot_password  password          Already Cracked/POT
 1465   nt         nt_password       password          Single

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
resource (hashes_hashcat.rb)> use auxiliary/analyze/crack_windows
resource (hashes_hashcat.rb)> set action hashcat
action => hashcat
resource (hashes_hashcat.rb)> run
[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20190531-32645-186ea6l
[*] Wordlist file written out to /tmp/jtrtmp20190531-32645-12pwixd
[*] Checking lm hashes already cracked...
[*] Cracking lm hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=i26VXnSy --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3000 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-32645-186ea6l
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking lm hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=i26VXnSy --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=3000 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-32645-186ea6l /tmp/jtrtmp20190531-32645-12pwixd
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username      Cracked Password  Method
 -----  ---------  --------      ----------------  ------
 1470   lm         lm_password   [notfound]D       Incremental
 1471   lm         lm2_password  [notfound]D       Incremental

[*] Checking nt hashes already cracked...
[*] Cracking nt hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=6lfDPvji --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1000 --increment --increment-max=4 --attack-mode=3 --runtime=60 /tmp/hashes_tmp20190531-32645-186ea6l
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking nt hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=6lfDPvji --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=1000 --attack-mode=0 --runtime=60 /tmp/hashes_tmp20190531-32645-186ea6l /tmp/jtrtmp20190531-32645-12pwixd
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type  Username          Cracked Password  Method
 -----  ---------  --------          ----------------  ------
 1470   lm         lm_password       [notfound]D       Incremental
 1471   lm         lm2_password      [notfound]D       Incremental
 1472   nt         lm2_pot_password  password          Wordlist
 1473   nt         nt_password       password          Wordlist

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
                       lm_password       [notfound]D                                                               Password      
                       lm2_password      [notfound]D                                                               Password      
                       lm_password       PASSWORD                                                                  Password      
                       lm2_password      PASSWORD                                                                  Password      
                       lm_password       password                                                                  Password      
                       lm2_password      password                                                                  Password      
                       lm2_pot_password  password                                                                  Password      
                       nt_password       password                                                                  Password
```
