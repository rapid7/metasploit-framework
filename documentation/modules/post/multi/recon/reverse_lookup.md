## Vulnerable Application

This module reverse resolves an IP address or IP address range to hostnames.


## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/multi/recon/reverse_lookup`
1. Do: `set SESSION <session id>`
1. Do: `set ADDRESS <IP address>` or `set RANGE <IP address range>`
1. Do: `run`

## Options

### ADDRESS

IP address to resolve.

### RANGE

IP address range to resolve.


## Scenarios

### Windows Server 2016 (x86_64)

```
msf6 > use post/multi/recon/reverse_lookup 
msf6 post(multi/recon/reverse_lookup) > set address 1.1.1.1
address => 1.1.1.1
msf6 post(multi/recon/reverse_lookup) > set session 1
session => 1
msf6 post(multi/recon/reverse_lookup) > run

[*] Resolving 1.1.1.1
[+] 1.1.1.1 resolves to one.one.one.one
[*] Post module execution completed
```

### Solaris 11.3 (x86_64)

```
msf6 > use post/multi/recon/reverse_lookup 
msf6 post(multi/recon/reverse_lookup) > set address 1.1.1.1
address => 1.1.1.1
msf6 post(multi/recon/reverse_lookup) > set session 1
session => 1
msf6 post(multi/recon/reverse_lookup) > run

[*] Resolving 1.1.1.1
[+] 1.1.1.1 resolves to one.one.one.one
[*] Post module execution completed
```

### Ubuntu Linux 22.04.1 (x86_64)

```
msf6 > use post/multi/recon/reverse_lookup 
msf6 post(multi/recon/reverse_lookup) > set address 1.1.1.1
address => 1.1.1.1
msf6 post(multi/recon/reverse_lookup) > set session 1
session => 1
msf6 post(multi/recon/reverse_lookup) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_memread, stdapi_railgun_api
[*] Resolving 1.1.1.1
[+] 1.1.1.1 resolves to one.one.one.one
[*] Post module execution completed
```
