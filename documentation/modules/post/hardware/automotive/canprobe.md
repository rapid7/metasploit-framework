A basic fuzzer for CAN IDs.  It can scan through CAN IDs and probes each data section
with a set value.  The defualt is 0xFF. It can also iterate through all the possible
values for each byte as well.  It has no concept of what is going on and makes no
attempt to check for return packets.

## Options

  **STARTID**

  The CAN ID to start your scan from.

  **STOPID**

  The CAN ID to stop the CAN scan.  If no STOPID is specified it will only scan one ID (STARTID).

  **FUZZ**

  If true the data segment will iterate through all possiblities (0-255).

  **PROBEVALUE**

  The value to put at each data segment.  The default is 0xFF.  When Fuzz is enabled this value is ignored.

  **PADDING**

  If you need to pad out the packet to be 8 packets for each request you can set this value to something between 0-255.

  **CANBUS**

  The bus to scan.  See 'supported_buses' for a list of available buses.

## Scenarios

  To quickly test how a vehicle or ECU reacts to random data throughout the packet.  For instance, you
have identified some door controls using a certain CAN ID.  By probing the other values you can often identify
other door related functions.

Note:  This is not a scanner.  You would not want to run this against all the IDs in a car and expect (good) results.

```
hwbridge > run post/hardware/automotive/canprobe CANBUS=can0 STARTID=0x320 fuzz=true

[*] Probing 0x320...
[*] Probe Complete

```
