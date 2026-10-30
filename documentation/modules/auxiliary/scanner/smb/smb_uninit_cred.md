## Vulnerable Application

This module checks if a Samba target is vulnerable to CVE-2015-0240, an uninitialized variable credentials vulnerability in the `_netr_ServerPasswordSet` RPC call. This vulnerability affects Samba versions 3.5.x through 4.1.x and can lead to remote code execution.

### Vulnerable Versions

- Samba 3.5.0 - 3.5.9
- Samba 3.6.0 - 3.6.24
- Samba 4.0.0 - 4.0.24
- Samba 4.1.0 - 4.1.16

### Installation

#### Docker Installation (Vulnerable Samba 4.1.12)

```dockerfile
FROM ubuntu:14.04

RUN apt-get update && \
    apt-get install -y samba=2:4.1.6+dfsg-1ubuntu2 && \
    apt-get clean

# Configure Samba
RUN echo "[global]" > /etc/samba/smb.conf && \
    echo "   workgroup = WORKGROUP" >> /etc/samba/smb.conf && \
    echo "   server string = Vulnerable Samba Server" >> /etc/samba/smb.conf && \
    echo "   security = user" >> /etc/samba/smb.conf

EXPOSE 139 445

CMD ["smbd", "--foreground", "--no-process-group"]
```

Build and run:

```bash
docker build -t vulnerable-samba .
docker run -p 445:445 -p 139:139 vulnerable-samba
```

#### Manual Installation (Ubuntu 14.04)

```bash
# Install vulnerable Samba version
sudo apt-get install samba=2:4.1.6+dfsg-1ubuntu2

# Start Samba service
sudo service smbd start
```

## Verification Steps

1. Start msfconsole
2. Use the scanner module: `use auxiliary/scanner/smb/smb_uninit_cred`
3. Set the target: `set RHOSTS <target-ip>`
4. Optionally enable passive mode (version check only): `set PASSIVE true`
5. Run the scanner: `run`

### Passive Check (Version-based Detection)

```
msf6 > use auxiliary/scanner/smb/smb_uninit_cred
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set PASSIVE true
msf6 auxiliary(scanner/smb/smb_uninit_cred) > run

[*] 192.168.1.100:445 - Samba version: Samba 4.1.12
[+] 192.168.1.100:445 - The target appears to be vulnerable to CVE-2015-0240.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Active Check (Exploit Trigger-based Detection)

```
msf6 > use auxiliary/scanner/smb/smb_uninit_cred
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set PASSIVE false
msf6 auxiliary(scanner/smb/smb_uninit_cred) > run

[*] 192.168.1.100:445 - Samba version: Samba 4.1.12
[+] 192.168.1.100:445 - The target is vulnerable to CVE-2015-0240.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Options

### PASSIVE

Enables passive checking via banner/version detection instead of actively triggering the vulnerability. When set to `true`, the module performs a safe version check. When `false` (default), it actively attempts to trigger the bug to confirm exploitability.

- Set to `true` for stealth scanning
- Set to `false` for definitive confirmation (may cause service disruption)

### RHOSTS

The target address range or CIDR identifier.

### THREADS

Number of concurrent threads for scanning multiple hosts (default: 1).

## Scenarios

### Samba 4.1.6 on Ubuntu 14.04 LTS (Docker)

```
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set RHOSTS 172.17.0.2
RHOSTS => 172.17.0.2
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set PASSIVE false
PASSIVE => false
msf6 auxiliary(scanner/smb/smb_uninit_cred) > run

[*] 172.17.0.2:445 - Samba version: Samba 4.1.6-Ubuntu
[+] 172.17.0.2:445 - The target is vulnerable to CVE-2015-0240.
[*] 172.17.0.2:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Samba 3.6.23 on Debian 7

```
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set RHOSTS 10.0.0.50
RHOSTS => 10.0.0.50
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set PASSIVE true
PASSIVE => true
msf6 auxiliary(scanner/smb/smb_uninit_cred) > run

[*] 10.0.0.50:445 - Samba version: Samba 3.6.23
[+] 10.0.0.50:445 - The target appears to be vulnerable to CVE-2015-0240.
[*] 10.0.0.50:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Patched Samba 4.2.0

```
msf6 auxiliary(scanner/smb/smb_uninit_cred) > set RHOSTS 192.168.1.200
RHOSTS => 192.168.1.200
msf6 auxiliary(scanner/smb/smb_uninit_cred) > run

[*] 192.168.1.200:445 - Samba version: Samba 4.2.0
[*] 192.168.1.200:445 - The target appears to be safe
[*] 192.168.1.200:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
