## Vulnerable Application

This module runs a rogue IPv6 router that advertises the attacker as the
recursive DNS server (RDNSS, RFC 8106) inside ICMPv6 Router Advertisements, and
a paired DNS server that poisons names under a target domain to point at the
attacker while transparently forwarding every other lookup so the victim stays
functional.

It is the Router Advertisement equivalent of the mitm6 DHCPv6 DNS takeover
(`auxiliary/spoof/dhcp/dhcpv6_dns_takeover`): instead of answering DHCPv6
solicits, it multicasts Router Advertisements carrying an RDNSS option, which
modern Windows and other RFC 8106 clients adopt as their IPv6 resolver. It also
listens for Router Solicitations and replies with an immediate unicast Router
Advertisement, so a client is coerced the moment it boots or refreshes rather
than waiting for the next unsolicited advertisement.

By default the advertised router lifetime is 0, so the attacker does not become
the client's default gateway; only DNS is taken over, which keeps routing
untouched and stays closer to mitm6's behaviour. Set `BECOME_ROUTER` to also act
as a router.

Paired with a Kerberos relay target such as `auxiliary/server/relay/esc8_kerberos`,
this is a native coercion half of the Kerberos relay via DNS technique
(CVE-2026-20929). This module requires root/administrator privileges to inject
raw ICMPv6 packets and Layer 2 adjacency to the victim.

## Verification Steps

1. Start `msfconsole` as root
1. Do: `use auxiliary/spoof/ipv6/ipv6_ra_dns_takeover`
1. Set `TARGET_DOMAIN` to the domain whose names you want to intercept
1. Set `SPOOF_IP6` to the attacker's IPv6 address
1. Set `INTERFACE` to the interface on the victim's segment
1. Do: `run`
1. Observe Router Advertisements being sent and in-scope DNS queries being poisoned

## Options

### TARGET_DOMAIN

The DNS domain to intercept. Names at or under this domain are poisoned; every
other lookup is forwarded. Required.

### TARGET_HOSTS

An optional space or semicolon separated list of specific FQDNs to poison. When
set, only these exact names are poisoned.

### SPOOF_IP6

The attacker's IPv6 address, advertised as the recursive DNS server (RDNSS) and
returned as the `AAAA` answer for poisoned names. Required.

### RELAY_CNAME

If set, poisoned names are answered with a `CNAME` to this name instead of a
direct address (the DNS-CNAME Kerberos relay trick), steering the victim onto a
name whose SPN the relay module presents to the target.

### RA_INTERVAL

Seconds between unsolicited Router Advertisements. Defaults to 30.

### RESPOND_TO_SOLICITS

Also reply to Router Solicitations with an immediate unicast Router
Advertisement, so a client is coerced as soon as it boots or refreshes rather
than waiting for the next interval. Enabled by default.

### ADVERTISE_SEARCH_DOMAIN

Advertise `TARGET_DOMAIN` as a DNS search list (DNSSL) so the client appends it
when resolving short names, helping steer it onto poisoned FQDNs. Enabled by
default.

### BECOME_ROUTER

Also advertise as the default router (router lifetime > 0). Disabled by default
so only DNS is taken over and routing is left untouched.

### INTERFACE / SMAC / SHOST

The interface to send Router Advertisements on, and optional overrides for the
source MAC and link-local source address.

## Scenarios

### RDNSS DNS takeover feeding a Kerberos ESC8 relay

Terminal 1 - start the coercion:

```
msf > use auxiliary/spoof/ipv6/ipv6_ra_dns_takeover
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set TARGET_DOMAIN ad.example.com
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set SPOOF_IP6 dead:beef::5
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set RELAY_CNAME attacker.ad.example.com
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > set INTERFACE eth0
msf auxiliary(spoof/ipv6/ipv6_ra_dns_takeover) > run
[*] DNS server started, poisoning names under ad.example.com -> CNAME attacker.ad.example.com
[*] Advertising dead:beef::5 as the IPv6 DNS server via Router Advertisements every 30s
[*] Responding to Router Solicitations with an immediate unicast RA
[+] Answered Router Solicitation from aa:bb:cc:dd:ee:ff (fe80::5) -> RDNSS dead:beef::5
[+] Poisoned ca.ad.example.com (AAAA) for fe80::5 -> CNAME attacker.ad.example.com
```

Terminal 2 - run the Kerberos ESC8 relay so the coerced authentication is
relayed to the CA (see `auxiliary/server/relay/esc8_kerberos`).

## Notes

* Requires root/administrator and Layer 2 adjacency; Router Advertisements are
  not routable.
* This is the Router Advertisement (RDNSS) coercion primitive.
  `auxiliary/spoof/dhcp/dhcpv6_dns_takeover` is the DHCPv6 equivalent; use
  whichever the target network responds to.
* RDNSS in Router Advertisements is honoured by modern Windows (RFC 8106); older
  clients may only accept DNS via DHCPv6, in which case use the DHCPv6 module.
