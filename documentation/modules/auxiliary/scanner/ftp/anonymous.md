## Description

This module allows us to scan through a series of IP Addresses and provide details whether anonymous access is allowed or not. By default, anonymous access is not allowed by the FTP server.

##Vulnerable Application

### Install ftp server on Kali Linux:

1.  ```apt-get install vsftpd```
2.Allow local users to log in and to allow ftp uploads by editing file /etc/vsftpd.conf uncommenting the following:


```
local_enable=YES
write_enable=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
```
3. **For allowing anonymous access:**

```anonymous_enable=NO```
4. Create the file /etc/vsftpd.chroot_list and add the local users you want allow to connect to FTP server. Start service and test connections:
5.  ```service vsftpd start``` 



### Installing FTP for IIS 7.5 in Windows:

### IIS 7.5 for Windows Server 2008 R2

1. On the taskbar, click Start, point to Administrative Tools, and then click Server Manager.
2. In the Server Manager hierarchy pane, expand Roles, and then click Web Server (IIS).
3. In the Web Server (IIS) pane, scroll to the Role Services section, and then click Add Role Services.
4. On the Select Role Services page of the Add Role Services Wizard, expand FTP Server.
5. Select FTP Service. (Note: To support ASP.NET Membership or IIS Manager authentication for the FTP service, you will also need to select FTP Extensibility.)
6. Click Next.
7. On the Confirm Installation Selections page, click Install.
8.On the Results page, click Close. 

### IIS 7.5 for Windows 7

1. On the taskbar, click Start, and then click Control Panel.
2. In Control Panel, click Programs and Features, and then click Turn Windows Features on or off.
3. Expand Internet Information Services, then FTP Server.
4. Select FTP Service. (Note: To support ASP.NET Membership or IIS Manager authentication for the FTP service, you will also need to select FTP Extensibility.)
5. Click OK. 

##Verification steps

```
msf > use auxiliary/scanner/ftp/anonymous
msf auxiliary(anonymous) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf auxiliary(anonymous) > set RPORT 21
RPORT => 21
msf auxiliary(anonymous) > exploit

[+] 127.0.0.1:21          - 127.0.0.1:21 - Anonymous READ (220 (vsFTPd 3.0.3))
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(anonymous) > 
```



