## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `INFO FILESYS` command to enumerate all storage volumes available on the printer, after first initialising volumes 0, 1, and 2 with `FSINIT`.

Printer volumes typically correspond to physical or virtual storage devices: onboard flash memory, RAM disk, optional hard drive, or CompactFlash card. The volume listing reveals which storage types are present, their total capacity, and the amount of free space.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented PJL filesystem enumeration; this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_list_volumes`
3. Do: `set RHOSTS [target IP or range]`
4. Do: `run`
5. A successful response prints the filesystem/volume listing and stores it as a note of type `printer.vol.listing` in the Metasploit database.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Volume enumeration on a multi-volume printer

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_list_volumes
msf6 auxiliary(scanner/printer/printer_list_volumes) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_list_volumes) > run

[+] 192.168.1.45:9100 - LABEL=0 TYPE=DISK TOTAL=20971520 FREE=15728640 PROTECT=FALSE LABEL=1 TYPE=RAMDISK TOTAL=4194304 FREE=4194304 PROTECT=FALSE LABEL=2 TYPE=ROM TOTAL=8388608 FREE=0 PROTECT=TRUE
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
