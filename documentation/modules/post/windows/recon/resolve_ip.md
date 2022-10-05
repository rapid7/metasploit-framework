## Vulnerable Application

This module reverse resolves an IP address or IP address range to hostnames.


## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/recon/resolve_ip`
4. Do: `set SESSION <session id>`
5. Do: `set ADDRESS <IP address>` or `set RANGE <IP address range>`
6. Do: `run`

## Options

### ADDRESS

IP address to resolve.

### RANGE

IP address range to resolve.


## Scenarios

### Windows Server 2016 (x64)

```
msf6 > use post/windows/recon/resolve_ip
msf6 post(windows/recon/resolve_ip) > set address 1.1.1.1
address => 1.1.1.1
msf6 post(windows/recon/resolve_ip) > set session 1
session => 1
msf6 post(windows/recon/resolve_ip) > run

[*] Resolving 1.1.1.1
[+] 1.1.1.1 resolves to one.one.one.one
[*] Post module execution completed
msf6 post(windows/recon/resolve_ip) > 
```
