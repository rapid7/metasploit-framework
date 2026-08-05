## Vulnerable Application

This module targets networked printers that expose the Printer Job Language (PJL) interface on TCP port 9100 (HP JetDirect / AppSocket). It reads, and optionally modifies, the "ready message" — the text displayed on the printer's front-panel LCD when the device is idle.

Three actions are available: **Scan** (read the current message), **Change** (set a new message), and **Reset** (clear the message back to the device default). The `Change` and `Reset` actions are write operations that persist on the device until explicitly cleared or the printer is power-cycled.

The PRET project ([https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)) documented PJL ready-message manipulation; this module is built on the Rex::Proto::PJL library, which draws from that research.

No authentication is required by default on most PJL implementations.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/printer_ready_message`
3. Do: `set RHOSTS [target IP or range]`
4. Do: `run` (uses the default `Scan` action)
5. A successful response prints the current ready message and stores it as a note of type `printer.rdymsg` in the Metasploit database.

To change the message:

1. Do: `set ACTION Change`
2. Do: `set MESSAGE "your text here"`
3. Do: `run`

To reset the message to device default:

1. Do: `set ACTION Reset`
2. Do: `run`

## Options

### RHOSTS

The target host(s) or range to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the printer's PJL/JetDirect interface is listening. (Default: `9100`)

### MESSAGE

The ready message string to set when using the `Change` action. Has no effect when the action is `Scan` or `Reset`. (Default: `PC LOAD LETTER`, Optional)

### ACTION

Selects the operation to perform:
- `Scan` — read and report the current ready message (Default)
- `Change` — write the value of `MESSAGE` to the printer's display
- `Reset` — clear the ready message

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Scanning ready messages across a subnet

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/printer_ready_message
msf6 auxiliary(scanner/printer/printer_ready_message) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf6 auxiliary(scanner/printer/printer_ready_message) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/printer/printer_ready_message) > run

[+] 192.168.1.45:9100 - READY
[+] 192.168.1.67:9100 - READY
[+] 192.168.1.102:9100 - OUT OF PAPER - TRAY 2
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Changing the ready message on a single host

```
msf6 auxiliary(scanner/printer/printer_ready_message) > set RHOSTS 192.168.1.45
RHOSTS => 192.168.1.45
msf6 auxiliary(scanner/printer/printer_ready_message) > set ACTION Change
ACTION => Change
msf6 auxiliary(scanner/printer/printer_ready_message) > set MESSAGE "CALL IT SECURITY"
MESSAGE => CALL IT SECURITY
msf6 auxiliary(scanner/printer/printer_ready_message) > run

[+] 192.168.1.45:9100 - CALL IT SECURITY
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
