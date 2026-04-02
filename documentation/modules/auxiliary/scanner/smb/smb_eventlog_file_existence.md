## Vulnerable Application

This module targets the MS-EVEN (EventLog Remoting Protocol) RPC service on Windows.
The ElfrOpenBELW function performs a `CreateFile` operation on the server, and the
resulting NTSTATUS error code reveals whether a given file or directory path exists.

This works with low-privileged domain credentials against any machine running the
EventLog service (enabled by default on Windows 11 and Windows Server 2025).
In a domain environment, the Program Files directory is readable by the Users group,
allowing enumeration of installed software on remote machines.

This technique was discovered by SafeBreach Labs as part of CVE-2025-29969 research.
While the TOCTOU arbitrary file write vulnerability was patched in May 2025, the
file existence check primitive remains functional and is not considered a vulnerability
by Microsoft.

### Affected Systems

- Windows 11 (all versions) — EventLog service enabled by default
- Windows Server 2025 — EventLog service enabled by default
- Windows 10 — EventLog service enabled by default
- Earlier Windows versions with the EventLog service running

### Requirements

- Valid domain or local credentials (low-privileged is sufficient)
- Network access to SMB (port 445 or 139)
- The EventLog service must be running on the target (default on modern Windows)

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/smb/smb_eventlog_file_existence`
3. Do: `set RHOSTS <target_ip>`
4. Do: `set SMBUser <username>`
5. Do: `set SMBPass <password>`
6. Do: `set SMBDomain <domain>`
7. Do: `set FILE_PATH C:\Program Files\Wireshark`
8. Do: `run`
9. Verify the module reports whether the path exists, is a directory, or does not exist

## Options

### FILE_PATH

A single remote file system path to check for existence. For example:
`C:\Program Files\Wireshark` or `C:\Windows\System32\cmd.exe`.

### FILE_PATHS_FILE

Path to a local file containing remote paths to check, one per line.
Lines starting with `#` are treated as comments and ignored.

Paths with drive letters (e.g. `C:\Windows`) are automatically converted to
NT native path format (`\??\C:\Windows`) for compatibility across all Windows versions.

## Scenarios

### Checking for installed software

```
msf > use auxiliary/scanner/smb/smb_eventlog_file_existence
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set rhosts 192.0.2.1
rhosts => 192.0.2.1
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbuser user
smbuser => user
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbpass password
smbpass => password
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbdomain .
smbdomain => .
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set file_path C:\\Program Files\\VMware\\VMware Tools\\7za.exe
file_path => C:\Program Files\VMware\VMware Tools\7za.exe
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > run
[+] 192.0.2.1:445 - C:\Program Files\VMware\VMware Tools\7za.exe - Exists (file)
[*] 192.0.2.1:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


### Checking for a list of installed software

```
msf > use auxiliary/scanner/smb/smb_eventlog_file_existence
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set rhosts 192.0.2.1
rhosts => 192.0.2.1
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbuser user
smbuser => user
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbpass password
smbpass => password
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set smbdomain .
smbdomain => .
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > set file_paths_file /home/user/programs.txt
file_paths_file => /home/user/programs.txt
msf auxiliary(scanner/smb/smb_eventlog_file_existence) > run
[+] 192.0.2.1:445 - C:\Program Files - Exists (directory)
[+] 192.0.2.1:445 - C:\Program Files\VMware - Exists (directory)
[+] 192.0.2.1:445 - C:\Program Files\VMware\VMware Tools\7za.exe - Exists (file)
[+] 192.0.2.1:445 - C:\windows\system32\cmd.exe - Exists (file)
[*] 192.0.2.1:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
