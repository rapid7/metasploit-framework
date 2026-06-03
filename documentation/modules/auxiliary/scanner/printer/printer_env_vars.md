## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It uses the PJL `INFO VARIABLES` command to retrieve all configurable printer environment variables, which can include paper tray settings, resolution, power-save timeout, job timeout, language settings, and similar device configuration data.

PJL is a printer control language originally developed by HP and supported by many manufacturers including Lexmark, Xerox, Brother, and Ricoh. The `INFO VARIABLES` command is part of the base PJL specification and is broadly available on compliant devices.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented the scope of information exposed through PJL; this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_env_vars`
3. Do: `set RHOSTS [target IP or range]`
4. Do: `run`
5. A successful response prints the environment variable block and stores it as a note of type `printer.env.vars` in the Metasploit database.

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### HP LaserJet environment variable enumeration

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_env_vars
msf6 auxiliary(scanner/printer/printer_env_vars) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_env_vars) > run

[+] 192.168.1.45:9100 - PAPER=LETTER [LETTER LEGAL A4 COM10 DL MONARCH C5 EXECUTIVE LEDGER A3 CUSTOM]
COPIES=1 [1 INTRANGE 1 999]
DUPLEX=OFF [OFF ON]
BINDING=LONGEDGE [LONGEDGE SHORTEDGE]
RESOLUTION=600 [300 600 1200]
ECONOMODE=OFF [OFF ON]
RET=ON [OFF LIGHT MEDIUM DARK ON]
DENSITY=3 [1 INTRANGE 1 5]
QTY=1 [1 INTRANGE 1 999]
TIMEOUT=15 [0 INTRANGE 0 3600]
SLEEP=30 [1 INTRANGE 1 240]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
