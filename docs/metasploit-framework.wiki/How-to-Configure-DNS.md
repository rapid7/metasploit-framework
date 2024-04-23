# Metasploit DNS
## Background
Most applications that need to handle hostname to IP address lookups rely on the host operating system, either by
passing the hostname directly to the socket-creation function or by calling a purpose built API such as `getaddrinfo`.
This was also how Metasploit handled name lookups and would only directly communicate with a DNS server when the request
was more involved than mapping a hostname to an IPv4 or IPv6 address.

One flaw in this approach is that when pivoting connections over a session, the DNS lookups would occur through the host
on which Metasploit was running instead of the compromised host from which the connection would originate. This lead to
two issues, the first being the aforementioned DNS leaks and the second that Metasploit could not always resolve
hostnames that the compromised system could.

Starting in Metasploit 6.4, Metasploit uses an internal DNS resolution system that grants the user a high degree of
control over the process of DNS queries.

## The DNS command
Metasploit's DNS configuration is controlled by the `dns` command which has multiple subcommands.

The current configuration can be printed by running `dns print`:

```msf6
msf6 > dns print
Default search domain: N/A
Default search list:   lab.lan
Current cache size:    0

Resolver rule entries
=====================

   #  Rule    Resolver    Comm channel
   -  ----    --------    ------------
   1  *                   
   .    \_    static      N/A
   .    \_    127.0.0.53  


Static hostnames
================

   Hostname                 IPv4 Address   IPv6 Address
   --------                 ------------   ------------
   localhost                127.0.0.1      ::1
     \_                     127.1.1.1      
   localhost.localdomain    127.0.0.1      ::1
   localhost4               127.0.0.1      
   localhost4.localdomain4  127.0.0.1      
   localhost6                              ::1
   localhost6.localdomain6                 ::1
```

The `help` subcommand can be used to display the available subcommands. The name of a subcommand can also be specified 
as an argument to `help` to display additional information about that subcommand, for example `dns help add`.

Metasploit's DNS system is composed of the following major components: resolver rules, static entries and the cache.

## DNS Resolver Rules
DNS resolver rules are a single wildcard that is associated with zero or more resolver types. When a query name matches
the wildcard expression, the associated resolvers are used in succession until one is capable of fulfilling the request.
For example, a wildcard pattern of `*.lab.lan` would match `www.lab.lan` and `_ldap._tcp.lab.lan`, but not `lab.lan` or
`msflab.lan`. Furthermore, the `*` wildcard pattern matches everything and should be used as a default rule.

Once a rule that matches the query name is found, the specified resolvers will be tried in order until one is capable of
handling the request. Different resolver types can be specified to handle queries in different ways. Rules are listed
in numeric order starting at position 1. Rules can be added to or removed from specific positions in a similar manner to
how iptables rules can be added to and removed from a specific chain.

### The Black Hole Resolver
The black hole resolver can be used to prevent queries from being resolved. It handles all query types and will prevent
resolvers defined after it from being used. The black hole resolver is specified by using the `black-hole` keyword.

### The Upstream Resolver
An upstream resolver can be used by specifying either an IPv4 or IPv6 address. When Metasploit uses this resolver, the
defined host will be contacted over the network. A session can optionally be defined through which network traffic will
be sent.

### The System Resolver
The system resolver can be used for hostname resolution to either IPv4 or IPv6 addresses by invoking the host operating
system's API. This is particularly useful in cases where the system's API is expected to be hooked by an external entity
such as proxychains. The system resolver is specified by using the `system` keyword. Queries that can not be fulfilled
by simply translating the query name to an IP address (e.g. PTR, TXT and SRV queries) will use the next resolver that is
configured in the rule.

### The Static Resolver
The static resolver can be used for hostname resolution to either IPv4 or IPv6 addresses through a static mapping that
is configured within Metasploit. This functionality is analogous to the `hosts` file found on many systems which defines
static hostname to IP address associations. The static resolver is specified by using the `static` keyword. Queries that
can not be fulfilled by simply translating the query name to an IP address (e.g. PTR, TXT and SRV queries) will use the
next resolver that is configured in the rule.

See [Static DNS Entries](#static-dns-entries) for configuring static entries.

### Example Rules

Define a single rule in the first position to handle all queries through three resolvers, first checking if there is a
static entry in Metasploit then using the system resolver and finally specifying an upstream DNS server to handle any
other query type.

```
dns add --index 1 --rule * static system 192.0.2.1
```

Append a rule to the end that will handle all queries for `*.lab.lan` using an upstream server contacted through session
1.

```
dns add --rule *.lab.lan --session 1 192.0.2.1
```

Append a rule to drop all queries for `*.noresolve.lan` using the black hole resolver.

```
dns add --rule *.noresolve.lan black-hole
```

## Static DNS Entries
Static entries used by the static resolver are configured through the `add-static` and `remove-static` subcommands. The
currently configured entries can be viewed in the `dns print` output and all entries can be flushed with the
`flush-static` subcommand. Static entries that are configured are shared across *all* rules in which a static resolver
is specified. In order for the static entry to be used, at least one rule must match the hostname, and that rule must be
configured to use the static resolver. A single hostname can be associated with multiple IP addresses and the same IP
address can be associated with multiple hostnames.

### Example Static Entries

Define static entries for `localhost` and common variations.

```
dns add-static localhost  127.0.0.1 ::1
dns add-static localhost4 127.0.0.1
dns add-static localhost6 ::1
```

Remove all static entries for `localhost`.

```
dns remove-static localhost
```

Remove all static entries.

```
dns flush-static
```

## The DNS Cache
DNS query replies are cached internally by Metasploit based on their TTL. This intends to minimize the amount of network
traffic required to perform the necessary lookups. The number of query replies that are currently cached is available in
the `dns print` output and all replies can be flushed with the `flush-cache` subcommand.

## Configuration Management
The DNS configuration can be saved using the `save` command from the `msfconsole` command context. Once saved, the
settings will be automatically restored the next time Metasploit starts up. Any changes that are made at runtime will be
lost when Metasploit exits, unless the `save` command is used.

### Resetting the Configuration
The DNS configuration can be restored to the default state by using the `reset-config` subcommand. The default
configuration:

* Populates the static entries from the host operating system's `hosts` file
* Defines a single rule that matches all query names whose first resolver is the `static` resolver and the remaining
  resolvers are set from the host operating systems' resolv.conf file

## Resolving hostnames
The `resolve` subcommand can be used to resolve a hostname to either an IPv4 or IPv6 address. In doing so, the rule that
was used to define the resolvers will be printed allowing the wildcard matching logic to be tested.
