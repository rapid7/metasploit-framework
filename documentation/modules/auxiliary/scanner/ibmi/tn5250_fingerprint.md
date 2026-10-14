## Vulnerable Application

This module connects to a TN5250(E) service (default port 23), completes
telnet option negotiation, and renders the pre-authentication signon panel
to fingerprint an IBM i (AS/400) host. It reports the system name,
subsystem, and device name parsed from the panel, plus negotiation-layer
metadata: TN5250E support, negotiated device type/geometry, NEW-ENVIRON
codepage/keyboard-type offers, and whether the server offers the IBMRSEED
encrypted/auto-signon path (RFC 4777). This module does not attempt
authentication, exercise the auto-signon path, or send credentials --
it is read-only reconnaissance.

This module was developed and tested against a live IBM i host.

### Limitations

- This module only handles TN5250E (enhanced) negotiation. A host that
  offers plain TN5250 without EOR/BINARY support will time out rather
  than being fingerprinted.
- The screen renderer handles the SBA, RA, IC and SF orders (including
  Field Format Words and Field Control Words) used by the signon panel.
  Other 5250 orders are treated as literal data.
- The device name is assigned per session, so it differs between runs.

## Verification Steps

1. Do: `use auxiliary/scanner/ibmi/tn5250_fingerprint`
2. Do: `set RHOSTS [IP or hostname]`
3. Do: `run`

## Options

### TIMEOUT

Timeout in seconds for negotiation and each record read. Default: `10`.

### TERM_TYPE

TN5250 terminal type offered during negotiation. Default: `IBM-3179-2`.

## Scenarios

### IBM i 7.5 host

```
msf > use auxiliary/scanner/ibmi/tn5250_fingerprint
msf auxiliary(scanner/ibmi/tn5250_fingerprint) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf auxiliary(scanner/ibmi/tn5250_fingerprint) > run

[+] 192.0.2.10:23      - System name:  DEMOSYS
[+] 192.0.2.10:23      - Subsystem:    QINTER
[+] 192.0.2.10:23      - Device:       QPADEV003Q
[*] 192.0.2.10:23      - TN5250E:     supported
[+] 192.0.2.10:23      - Encrypted/auto-signon offered (IBMRSEED)
[!] 192.0.2.10:23      - Cleartext TN5250 on 23
[*] 192.0.2.10:23         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
