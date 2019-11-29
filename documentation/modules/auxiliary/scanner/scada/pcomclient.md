## Vulnerable Application

  Unitronics Vision PLCs using PCOM protocol

## Verification Steps

  1. Do: `use scanner/scada/pcomclient`
  2. Do: `set RHOST=IP` where IP is the IP address of the target
  3. Do: `run` to send PCOM command

 ## Scenarios

   ```
msf > use scanner/scada/pcomclient
msf auxiliary(scanner/scada/pcomclient) > show options

Module options (auxiliary/scanner/scada/pcomclient):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ADDRESS  0                yes       PCOM memory address (0 - 65535)
   LENGTH   3                yes       Number of values to read (1 - 255) (read only)
   OPERAND  MI               yes       Operand type (Accepted: Input, Output, SB, MB, MI, SI, ML, SL)
   RHOST                     yes       The target address
   RPORT    20256            yes       The target port (TCP)
   UNITID   0                no        Unit ID (0 - 127)
   VALUES                    no        Values to write (0 - 65535 each) (comma separated) (write only)


Auxiliary action:

   Name  Description
   ----  -----------
   READ  Read values from PLC memory


msf auxiliary(scanner/scada/pcomclient) > set RHOST 192.168.1.1
RHOST => 192.168.1.1
msf auxiliary(scanner/scada/pcomclient) > run

[*] 192.168.1.1:20256 - Reading 03 values (MI) starting from 0000 address
[+] 192.168.1.1:20256 - [00000] : 0
[+] 192.168.1.1:20256 - [00001] : 1
[+] 192.168.1.1:20256 - [00002] : 0
[*] Auxiliary module execution completed
msf auxiliary(scanner/scada/pcomclient) >
```
