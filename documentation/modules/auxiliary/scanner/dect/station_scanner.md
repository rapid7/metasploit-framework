## Description

This module scans for DECT (Digital Enhanced Cordless Telecommunications) base stations using a COM-ON-AIR (COA) compatible adapter. DECT is a wireless technology commonly used for cordless phones, baby monitors, and other wireless communication devices.

The scanner identifies base stations by their RFPI (Radio Fixed Part Identity), which is a unique identifier for each DECT base station.

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
2. Do: `use auxiliary/scanner/dect/station_scanner`
3. Do: `set INTERFACE <your_dect_interface>`
4. Do: `run`
5. You should see discovered DECT base stations with their RFPI and channel information

## Options

### INTERFACE

The DECT/COA interface to use for scanning. This should be set to the interface name of your COM-ON-AIR card.

### BAND

The frequency band to scan. DECT operates on different frequency bands depending on the region:
- **EMEA**: 1880-1900 MHz (Europe, Middle East, Africa)
- **US**: 1920-1930 MHz (United States - DECT 6.0)
- Other regional variants may apply

## Scenarios

### Scanning for DECT Base Stations

This scenario demonstrates discovering DECT base stations in range.

```
msf6 > use auxiliary/scanner/dect/station_scanner
msf6 auxiliary(scanner/dect/station_scanner) > set INTERFACE dect0
INTERFACE => dect0
msf6 auxiliary(scanner/dect/station_scanner) > run

[*] Opening interface: dect0
[*] Using band: EMEA
[*] Changing to fp scan mode.
[*] Scanning...
[+] Found New RFPI: 00:11:22:33:44
[+] Found New RFPI: 00:AA:BB:CC:DD
[*] Closing interface

RFPI            Channel
00:11:22:33:44  5
00:AA:BB:CC:DD  3

[*] Auxiliary module execution completed
```

## References

- [DECT Security Research](https://web.archive.org/web/20210210224853/https://dedected.org/trac)
- [COM-ON-AIR Documentation](https://github.com/znuh/COA)
