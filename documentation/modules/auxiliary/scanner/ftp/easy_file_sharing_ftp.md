This module exploits a directory traversal vulnerability in Easy File Sharing FTP Server 3.6, or
prior. It abuses the RETR command in FTP in order to retrieve a file outside the shared directory.

By default, anonymous access is allowed by the FTP server.

## Vulnerable Application

Easy File Sharing FTP Server version 3.6 or prior should be affected. You can download the
vulnerable application from the official website:

http://www.efssoft.com/efsfs.exe

## Options

Since the FTP server allows anonymous access, by default, you only need to configure:

**RHOSTS**

The FTP server IP address.

**PATH**

The file you wish to download. Assume this path starts from C:\

## Demonstration

![ftp](https://cloud.githubusercontent.com/assets/1170914/23971054/4fdc2b08-099a-11e7-88ea-67a678628e49.gif)
