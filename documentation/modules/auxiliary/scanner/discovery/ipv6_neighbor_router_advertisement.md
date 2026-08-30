## Vulnerable Application

This module discovers IPv6 hosts on the local network by sending spoofed
[router advertisement packets](https://datatracker.ietf.org/doc/rfc4861/) and listening for neighbor solicitations.

## Target Environment

This module is designed to be used on a local network segment where IPv6 is enabled.
It is effective for identifying hosts that are configured for IPv6 auto-configuration (SLAAC),
as they will respond to the router advertisement.
This is common in modern operating systems, including Windows, macOS, and various Linux distributions.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement`
3. Do: `set RHOSTS fe80::%eth0` (or your network interface)
4. Do: `run`
5. The module will begin sending router advertisements and report any discovered hosts.

## Options

### TIMEOUT_NEIGHBOR

This option specifies the time in seconds to listen for a neighbor solicitation response after sending a router advertisement.
The default value is `1`. Increasing this value may help discover slower hosts on the network,
but it will also increase the module's execution time.

## Scenarios

### Discovering IPv6 Hosts on a Local Network

The primary use of this module is to identify active IPv6 hosts on the local network segment.
This can be useful for building a target list for further scanning or assessment.
The module uses the `pcap` library to listen for `icmp6` traffic and `capture.inject` to send the spoofed router advertisement,
allowing it to operate at a low level on the network.

```
msf6 auxiliary(scanner/discovery/ipv6_neighbor_router_advertisement) > set RHOSTS fe80::%eth0
RHOSTS => fe80::%eth0
msf6 auxiliary(scanner/discovery/ipv6_neighbor_router_advertisement) > run

[*] Sending router advertisement...
[*] Listening for neighbor solicitation...
[+]    |*| 2001:db8:1:1:c0a8:1:a2b3:c4d5
[*] Attempting to solicit link-local addresses...
[+]    |*| fe80::c0a8:1:a2b3:c4d5 -> 00:0c:29:12:34:56
[*] Auxiliary module execution completed
