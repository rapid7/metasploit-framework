## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). PJL is a printer control language originally developed by HP and subsequently supported by many manufacturers including Lexmark, Xerox, Brother, Ricoh, and others. The `INFO ID` command, which this module uses, is part of the base PJL specification and is broadly implemented.

The module sends a PJL `INFO ID` request and captures the device identification string returned by the printer. This string typically includes the manufacturer name, model, firmware version, and sometimes memory information.

The PRET (Printer Exploitation Toolkit) project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented the attack surface of PJL-speaking printers; the Rex::Proto::PJL library used by this and related modules draws from that research.

No authentication is required by default on most PJL implementations. The module works against any printer with TCP/9100 open and PJL enabled.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_version_info`
3. Do: `set RHOSTS [target IP or range]`
4. Do: `run`
5. A successful response prints the device identification string and records the host as a `jetdirect` service in the Metasploit database.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### HP LaserJet on TCP/9100

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_version_info
msf6 auxiliary(scanner/printer/printer_version_info) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf6 auxiliary(scanner/printer/printer_version_info) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/printer/printer_version_info) > run

[+] 192.168.1.45:9100 - HP LASERJET 4200 SERIES, ROM: 20020823 05.013.0, RAM: 64MB
[+] 192.168.1.67:9100 - Lexmark T650, Firmware: LHS60.JU.P230, Flash: 16MB, RAM: 32MB
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
