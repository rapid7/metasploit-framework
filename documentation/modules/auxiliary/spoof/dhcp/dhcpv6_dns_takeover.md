## Vulnerable Application

This module runs a rogue DHCPv6 server that hands the attacker to IPv6 clients
as their DNS server (the classic mitm6 primitive), together with a paired DNS
server that poisons names under a target domain to point at the attacker while
transparently forwarding every other lookup so the victim stays functional.

Windows prefers IPv6 over IPv4 and, by default, sends periodic DHCPv6 solicits.
By answering those solicits and advertising the attacker as the client's DNS
server, the module intercepts the victim's name resolution even on an IPv4-only
network. Once the victim resolves a target service through the attacker it can
be coerced into authenticating to the attacker.

Paired with a Kerberos relay target such as `auxiliary/server/relay/esc8_kerberos`,
this is the native coercion half of the Kerberos relay via DNS technique
(CVE-2026-20929), removing the dependency on external tooling such as mitm6. Set
`RELAY_CNAME` to steer the victim onto a name whose SPN the relay module will
present to the CA.

This module requires root/administrator privileges to bind the DHCPv6 port
(UDP/547) and join the DHCPv6 multicast group, and Layer 2 adjacency to the
victim.

## Verification Steps

1. Start `msfconsole` as root
1. Do: `use auxiliary/spoof/dhcp/dhcpv6_dns_takeover`
1. Set `TARGET_DOMAIN` to the domain whose names you want to intercept
1. Set `SPOOF_IP6` to the attacker's IPv6 address
1. Do: `run`
1. Observe DHCPv6 solicits being answered and in-scope DNS queries being poisoned

## Options

### TARGET_DOMAIN

The DNS domain to intercept. Names at or under this domain are poisoned; every
other lookup is transparently forwarded. Required.

### TARGET_HOSTS

An optional space or semicolon separated list of specific FQDNs to poison. When
set, only these exact names are poisoned and all other names (including other
names under `TARGET_DOMAIN`) are forwarded.

### SPOOF_IP6

The attacker's IPv6 address. It is handed to clients as their DNS server and is
returned as the `AAAA` answer for poisoned names. Required.

### RELAY_CNAME

If set, poisoned names are answered with a `CNAME` to this name instead of a
direct address. This is the DNS-CNAME trick used for Kerberos relay: the victim
follows the CNAME to a name whose SPN the relay module presents to the target,
while the Kerberos ticket is still issued for the original service.

### LEASE_IP6

An optional IPv6 address to lease to clients that make a stateful (IA_NA)
request. Not required for DNS takeover.

### DHCPV6_INTERFACE

The network interface to bind the DHCPv6 server and join the multicast group on.
Defaults to the primary interface.

## Scenarios

### mitm6-style DNS takeover feeding a Kerberos ESC8 relay

Terminal 1 - start the coercion:

```
msf > use auxiliary/spoof/dhcp/dhcpv6_dns_takeover
msf auxiliary(spoof/dhcp/dhcpv6_dns_takeover) > set TARGET_DOMAIN ad.example.com
msf auxiliary(spoof/dhcp/dhcpv6_dns_takeover) > set SPOOF_IP6 dead:beef::5
msf auxiliary(spoof/dhcp/dhcpv6_dns_takeover) > set RELAY_CNAME attacker.ad.example.com
msf auxiliary(spoof/dhcp/dhcpv6_dns_takeover) > run
[*] DNS server started, poisoning names under ad.example.com -> CNAME attacker.ad.example.com
[*] DHCPv6 server started, advertising dead:beef::5 as the DNS server
[*] DHCPv6 SOLICIT from fe80::... answered with DNS dead:beef::5
[+] Poisoned ca.ad.example.com (AAAA) for fe80::... -> CNAME attacker.ad.example.com
```

Terminal 2 - run the Kerberos ESC8 relay so the coerced authentication is
relayed to the CA (see `auxiliary/server/relay/esc8_kerberos`).

## Notes

* Requires root/administrator and Layer 2 adjacency; DHCPv6 messages are not
  routable.
* This is the DHCPv6 coercion primitive. `auxiliary/spoof/ipv6/ipv6_ra_dns_takeover`
  is the Router Advertisement (RDNSS) equivalent; use whichever the target
  network responds to.
* Out-of-scope lookups are forwarded unchanged, so the victim keeps working and
  monitoring is less likely to notice broken name resolution.
