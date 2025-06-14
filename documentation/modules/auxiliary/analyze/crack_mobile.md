## Vulnerable Application

  This module attempts to use a password cracker to decode mobile (Android)
  based password hashes, such as:

  * `android-sha1` based passwords
  * `android-samsung-sha1` based passwords
  * `android-md5` based passwords

  Formats:

| Common               | John | Hashcat |
| -------------------- | ---- | ------- |
| android-md5          | n/a  | 10      |
| android-samsung-sha1 | n/a  | 5800    |
| android-sha1         | n/a  | 110     |

  Sources of hashes can be found here:
  [source](https://hashcat.net/forum/thread-2202.html)

## Verification Steps

  1. Have at least one user with a `android-sha1`, `android-samsung-sha1`, or `android-md5` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/crack_mobile```
  4. Do: set cracker of choice
  5. Do: ```run```
  6. You should hopefully crack a password.

## Actions

### hashcat

Use hashcat (default).

## Options

### MD5

Crack `android-md5` based passwords.  Default is `true`

### SHA1

Crack `android-sha1` (non-samsung) based passwords.  Default is `true`

### SAMSUNG

Crack `android-samsung-sha1` based passwords.  Default is `true`

### CONFIG

The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

### CRACKER_PATH

The absolute path to the cracker executable.  Default behavior is to search `path`.

### CUSTOM_WORDLIST

The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
`USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

### DeleteTempFiles

This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

### Fork

This option will set how many forks to use on john the ripper.  Default is `1` (no forking).

### INCREMENTAL

Run the cracker in incremental mode.  Default is `true`

### ITERATION_TIMEOUT

The max-run-time for each iteration of cracking

### KORELOGIC

Apply the [KoreLogic rules](http://contest-2010.korelogic.com/rules.html) to Wordlist Mode (slower).
Default is `false`.

### MUTATE

Apply common mutations to the Wordlist (SLOW).  Mutations are:

   * `'@' => 'a'`
   * `'0' => 'o'`
   * `'3' => 'e'`
   * `'$' => 's'`
   * `'7' => 't'`
   * `'1' => 'l'`
   * `'5' => 's'`

Default is `false`.

### POT

The path to a John POT file (JtR option: `--pot`) to use instead.  The `pot` file is the data file which
records cracked password hashes.  Kali linux's default location is `/root/.john/john.pot`.
Default is `~/.msf4/john.pot`.

### SHOWCOMMAND

Show the command being used run from the command line for debugging.  Default is `false`

### USE_CREDS

Use existing credential data saved in the database.  Default is `true`.

### USE_DB_INFO

Use looted database schema info to seed the wordlist.  This includes the Database Name, each Table Name,
and each Column Name.  If the DB is MSSQL, the Instance Name is also used.  Default is `true`.

### USE_DEFAULT_WORDLIST

Use the default metasploit wordlist in `metasploit-framework/data/wordlists/password.lst`.  Default is
`true`.

### USE_HOSTNAMES

   Seed the wordlist with hostnames from the workspace.  Default is `true`.

### USE_ROOT_WORDS

Use the Common Root Words Wordlist in `metasploit-framework/data/wordlists/common_roots.txt`.  Default
is true.

### WORDLIST

Run the cracker in dictionary/wordlist mode.  Default is `true`

## Scenarios

### Sample Data

The following is data which can be used to test integration, including adding entries
to a wordlist and pot file to test various aspects of the cracker.

```
creds add user:samsungsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-samsung-sha1
creds add user:androidsha1 hash:9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5 jtr:android-sha1
creds add user:androidmd5 hash:1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5 jtr:android-md5
```

### Hashcat

We'll set `ITERATION_TIMEOUT 60` for a quick crack, and `ShowCommand true` for easy debugging.

```
msf5 post(android/gather/hashdump) > creds add user:androidsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-sha1
msf5 post(android/gather/hashdump) > previous
msf5 auxiliary(analyze/crack_mobile) > set showcommand true
showcommand => true
msf5 auxiliary(analyze/crack_mobile) > run

[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20191112-9775-19hbg7j
[*] Wordlist file written out to /tmp/jtrtmp20191112-9775-f3q0r1
[*] Checking android-sha1 hashes already cracked...
[*] Cracking android-sha1 hashes in pin mode...
[*]    Cracking Command: /usr/bin/hashcat --session=UrEHXRVq --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --increment --increment-min=4 --increment-max=8 --attack-mode=3 --runtime=300 /tmp/hashes_tmp20191112-9775-19hbg7j ?d?d?d?d?d?d?d?d
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-sha1 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=UrEHXRVq --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --increment --increment-max=4 --attack-mode=3 /tmp/hashes_tmp20191112-9775-19hbg7j
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=UrEHXRVq --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --attack-mode=0 /tmp/hashes_tmp20191112-9775-19hbg7j /tmp/jtrtmp20191112-9775-f3q0r1
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type     Username     Cracked Password  Method
 -----  ---------     --------     ----------------  ------
 98     android-sha1  androidsha1  1234              Pin

[*] Auxiliary module execution completed

```

### MD5, SHA1, SAMSUNG

Create a password with each type, passwords are all `1234`.

```
msf5 > creds add user:samsungsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-samsung-sha1
msf5 > creds add user:androidsha1 hash:9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5 jtr:android-sha1
msf5 > creds add user:androidmd5 hash:1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5 jtr:android-md5
```

```
msf5 > use auxiliary/analyze/crack_mobile
msf5 auxiliary(analyze/crack_mobile) > run

[+] hashcat Version Detected: v5.1.0
[*] Hashes Written out to /tmp/hashes_tmp20191113-29506-1xydi7
[*] Wordlist file written out to /tmp/jtrtmp20191113-29506-aq6ph7
[*] Checking android-sha1 hashes already cracked...
[*] Cracking android-sha1 hashes in pin mode...
[*]    Cracking Command: /usr/bin/hashcat --session=ishUl4hb --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=110 --increment --increment-min=4 --increment-max=8 --attack-mode=3 --runtime=300 /tmp/hashes_tmp20191113-29506-1xydi7 ?d?d?d?d?d?d?d?d
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-sha1 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=ishUl4hb --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=110 --increment --increment-max=4 --attack-mode=3 /tmp/hashes_tmp20191113-29506-1xydi7
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=ishUl4hb --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=110 --attack-mode=0 /tmp/hashes_tmp20191113-29506-1xydi7 /tmp/jtrtmp20191113-29506-aq6ph7
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type     Username     Cracked Password  Method
 -----  ---------     --------     ----------------  ------
 127    android-sha1  androidsha1  1234              Pin

[*] Checking android-samsung-sha1 hashes already cracked...
[*] Cracking android-samsung-sha1 hashes in pin mode...
[*]    Cracking Command: /usr/bin/hashcat --session=SMD3wSMl --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --increment --increment-min=4 --increment-max=8 --attack-mode=3 --runtime=300 /tmp/hashes_tmp20191113-29506-1xydi7 ?d?d?d?d?d?d?d?d
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-samsung-sha1 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=SMD3wSMl --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --increment --increment-max=4 --attack-mode=3 /tmp/hashes_tmp20191113-29506-1xydi7
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-samsung-sha1 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=SMD3wSMl --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=5800 --attack-mode=0 /tmp/hashes_tmp20191113-29506-1xydi7 /tmp/jtrtmp20191113-29506-aq6ph7
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type             Username     Cracked Password  Method
 -----  ---------             --------     ----------------  ------
 126    android-samsung-sha1  samsungsha1  1234              Pin
 127    android-sha1          androidsha1  1234              Pin

[*] Checking android-md5 hashes already cracked...
[*] Cracking android-md5 hashes in pin mode...
[*]    Cracking Command: /usr/bin/hashcat --session=outBsYDa --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=10 --increment --increment-min=4 --increment-max=8 --attack-mode=3 --runtime=300 /tmp/hashes_tmp20191113-29506-1xydi7 ?d?d?d?d?d?d?d?d
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-md5 hashes in incremental mode...
[*]    Cracking Command: /usr/bin/hashcat --session=outBsYDa --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=10 --increment --increment-max=4 --attack-mode=3 /tmp/hashes_tmp20191113-29506-1xydi7
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking android-md5 hashes in wordlist mode...
[*]    Cracking Command: /usr/bin/hashcat --session=outBsYDa --logfile-disable --potfile-path=/root/.msf4/john.pot --hash-type=10 --attack-mode=0 /tmp/hashes_tmp20191113-29506-1xydi7 /tmp/jtrtmp20191113-29506-aq6ph7
nvmlDeviceGetFanSpeed(): Not Supported

[+] Cracked Hashes
==============

 DB ID  Hash Type             Username     Cracked Password  Method
 -----  ---------             --------     ----------------  ------
 126    android-samsung-sha1  samsungsha1  1234              Pin
 127    android-sha1          androidsha1  1234              Pin
 128    android-md5           androidmd5   1234              Pin

[*] Auxiliary module execution completed
```
