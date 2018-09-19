## Introduction
This module gathers several pieces of information from the vehicle.  First it reports
the available PIDS for pulling realtime current_data from Mode $01.  If some of
the common PIDs are returned it will print those as well, such as Engine Temp and
Vehicle speed.  If there are any Diagnostic Trouble Codes (DTCs) it will list those.
The DTCs and Engine Light can be cleared by setting the optional CLEAR_DTC to true.
Finally it gathers Vehicle information via UDS Mode $09 requests.  The module
first probes Mode $09 PID $00 to determine what all PIDs are supported then
iterates through them and prints the response.  The module will format known
PIDs to ASCII.

## Options ##

  **SRCID**

  This is the SRC CAN ID for the ISO-TP connection.  Default is 0x7E0.

  **DSTID**

  This is the CAN ID of the expected response.  Default is 0x7E8.

  **CANBUS**

  Determines which CAN bus to communicate on.  Type 'supported_buses' for valid options.

  **CLEAR_DTCS**

  If any Diagnostic Trouble Codes (DTCs) are present it will clear those and reset the MIL (Engine Light).

  **PADDING**

  Optional byte-value to use for padding all CAN bus packets to an 8-byte length.  Padding is disabled by default.

  **FC**

  Optional.  If true forces sending flow control packets on all multibyte ISO-TP requests

## Scenarios

  Given a standard vehicle ECU that is connected to can2 of the HWBridge device:

```
hwbridge > run post/hardware/automotive/getvinfo CANBUS=can2

[*] Avaiable PIDS for pulling realitme data: 46 pids
[*]   [1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 24, 25, 28, 31, 32, 32, 33, 44, 45, 46, 47, 48, 49, 50, 51, 60, 61, 64, 65, 66, 67, 68, 69, 70, 71, 73, 74, 76]
[*]   MIL (Engine Light) : OFF
[*]   Number of DTCs: 0
[*]   Engine Temp: 140 °C / 284 °F
[*]   RPMS: 0
[*]   Speed: 0 km/h  /  0.0 mph
[*] Supported OBD Standards: OBD and OBD-II
[*] Mode $09 Vehicle Info Supported PIDS: [2, 4, 6, 8]
[*] VIN: 1G1ZT53826F109149
[*] Calibration ID: UDS ERR: {"RCRRP"=>"Request Correctly Received, but Response is Pending"}
[*] PID 6 Response: ["00", "00", "C4", "E9", "00", "00", "17", "33", "00", "00", "00", "00"]
[*] PID 8 Response: ["00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"]
```
