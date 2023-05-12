## Vulnerable Application

This is an auxiliary for DOSing a VSFTPD server from version 2.3.3 and below.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/dos/ftp/vstfpd_232`
3. `set rhosts`
4. `set ftpuser`
5. `set ftppass`
6. `run`

## Scenarios

### VSFTPD 2.3.2 - Ubuntu 12.04

```
```
