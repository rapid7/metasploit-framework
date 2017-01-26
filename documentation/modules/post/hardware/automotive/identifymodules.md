Scans the CANBUS for devices responding to UDS DSC queries.  By trying to set
the Diagnostic Session Control (DSC) devices that support UDS will typically respond
with an error or an acknowldegment.  We use this information to map out modules in a vehicle.

## Options

  **STARTID**

  The CAN ID to start your scan from.

  **ENDID**

  The CAN ID to stop the CAN scan.

  **CANBUS**

  The bus to scan.  See 'supported_buses' for a list of available buses

## Scenarios

  A Quick scan of buses from 0x600 to 0x7FF

```
hwbridge > run post/hardware/automotive/identifymodules CANBUS=can2 STARTID=0x600

Starting scan...
[*] Identified module 7e0
Scanned 504 IDs and found 1 modules that responded
  7e0
```
