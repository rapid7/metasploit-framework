## Description

This module scans for active DECT (Digital Enhanced Cordless Telecommunications) calls using a COM-ON-AIR (COA) compatible adapter. Unlike the station scanner which identifies base stations, this module detects ongoing voice communications between DECT handsets and base stations.

The scanner monitors DECT channels for active call traffic and reports the RFPI (Radio Fixed Part Identity) of the base station handling the call, along with timing and channel information.

## Vulnerable Application

### Hardware Requirements

This module requires a **COM-ON-AIR (COA) compatible PCMCIA card** to function. These cards were originally designed for DECT communications and have been repurposed for security research.

Compatible hardware includes:
- Dosch & Amand COM-ON-AIR PCMCIA cards (Type II or Type III)
- Other COA-compatible adapters

### Software Requirements

- Linux operating system with COA driver support
- Proper kernel modules loaded for the COA card

### Setup Instructions

1. Insert the COM-ON-AIR PCMCIA card into your system
2. Load the appropriate kernel driver for the COA card
3. Verify the interface is available (typically appears as a network interface)

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/dect/call_scanner`
3. Do: `set INTERFACE <your_dect_interface>`
4. Do: `run`
5. You should see active DECT calls with their timestamp, RFPI, and channel information

## Options

### INTERFACE

The DECT/COA interface to use for scanning. This should be set to the interface name of your COM-ON-AIR card.

### BAND

The frequency band to scan. DECT operates on different frequency bands depending on the region:
- **EMEA**: 1880-1900 MHz (Europe, Middle East, Africa)
- **US**: 1920-1930 MHz (United States - DECT 6.0)
- Other regional variants may apply

## Scenarios

### Detecting Active DECT Calls

This scenario demonstrates detecting active DECT phone calls in range.

```
msf6 > use auxiliary/scanner/dect/call_scanner
msf6 auxiliary(scanner/dect/call_scanner) > set INTERFACE dect0
INTERFACE => dect0
msf6 auxiliary(scanner/dect/call_scanner) > run

[*] Opening interface: dect0
[*] Using band: EMEA
[*] Changing to call scan mode.
[*] Scanning...
[+] Found active call on: 00:11:22:33:44
[+] Found active call on: 00:AA:BB:CC:DD
[*] Closing interface

Time                            RFPI            Channel
2026-01-13 18:45:32 -0800       00:11:22:33:44  5
2026-01-13 18:46:15 -0800       00:AA:BB:CC:DD  3

[*] Auxiliary module execution completed
```

### Use Case: Security Assessment

During a physical security assessment, this module can be used to:
1. Identify if DECT phones are in active use
2. Determine the number of concurrent calls
3. Map DECT infrastructure based on active communications
4. Assess the exposure window of DECT communications

**Note**: Active call detection requires the calls to be in progress during the scan. The module continuously cycles through channels to maximize detection coverage.

## References

- [DECT Security Research](https://web.archive.org/web/20210210224853/https://dedected.org/trac)
- [COM-ON-AIR Documentation](https://github.com/znuh/COA)
