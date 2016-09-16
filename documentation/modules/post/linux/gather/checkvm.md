## Locations Checked

There are many locations that are checked for having evidence of being a virtual machine.  The follow is a list of them:

1. (with root access) `/usr/sbin/dmidecode`
2. `/sbin/lsmod`
3. `/proc/scsi/scsi`
4. `cat /proc/ide/hd*/model`
5. `lspci`
6. `ls -1 /sys/bus`
7. `lscpu`
8. `dmesg`

## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. Do: `use post/linux/gather/checkvm`
  4. Do: `set session <session>`
  5. Do: `run`
  6. You should get feedback if a virtual machine environment was detected

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`

## Scenarios

  Typical run against Kali with only one user (root), using ssh_login for initial shell

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
[*] Command shell session 1 opened (127.0.0.1:41521 -> 127.0.0.1:22) at 2016-09-14 00:14:36 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/linux/gather/checkvm 
msf post(checkvm) > set session 1
session => 1
msf post(checkvm) > run

[*] Gathering System info ....
[+] This appears to be a 'Xen' virtual machine
[*] Post module execution completed
  ```
A non-virtual machine will have the following output
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
[*] Command shell session 1 opened (127.0.0.1:41521 -> 127.0.0.1:22) at 2016-09-14 00:15:36 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/linux/gather/checkvm 
msf post(checkvm) > set session 1
session => 1
msf post(checkvm) > run

[*] Gathering System info ....
[*] This does not appear to be a virtual machine
[*] Post module execution completed
  ```
And a VMwave virtual machine
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
[*] Command shell session 1 opened (127.0.0.1:41521 -> 127.0.0.1:22) at 2016-09-14 00:18:36 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/linux/gather/checkvm 
msf post(checkvm) > set session 1
session => 1
msf post(checkvm) > run

[*] Gathering System info ....
[+] This appears to be a 'VMware' virtual machine
[*] Post module execution completed
```
