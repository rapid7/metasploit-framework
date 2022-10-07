## Description
This module uses a pfx certificate file to acquire a TGT using the PKINIT protocol. A successful login will store the TGT for use with other modules.

## Options

This module only requires the `RHOST` and `CERT_FILE` options to be set.

If the certificate file has a non-empty password, the `CERT_PASS` option must also be set.

The username and realm for the login request are derived from the certificate; however it is possible to override them using the `USERNAME` and `DOMAIN` options. These options must be provided if for some reason the certificate contains several principals. The module will provide a warning if these do not match any entry in the certificate.


## Verification Steps

1. Do: ```use auxiliary/admin/kerberos/pkinit_login```
1. Do: ```set RHOSTS [IP]```
1. Do: ```set CERT_FILE [path]```
1. Do: ```run```

## Scenarios


### Receive TGT from an existing certificate

You must first retrieve a certificate using another means, such as the `auxiliary/admin/dcerpc/icpr_cert` module

```
msf6 > use auxiliary/admin/kerberos/pkinit_login
msf6 auxiliary(admin/kerberos/pkinit_login) > set cert_file /home/user/msf.pfx
cert_file => /home/user/msf.pfx
msf6 auxiliary(admin/kerberos/pkinit_login) > set rhosts 192.168.1.1
rhosts => 192.168.1.1
msf6 auxiliary(admin/kerberos/pkinit_login) > run
[*] Running module against 192.168.1.1

[*] Attempting PKINIT login for Administrator@pod8.lan
[+] Successfully authenticated with certificate
[*] 192.168.1.1:88 - TGT MIT Credential Cache saved to /home/user/.msf4/loot/20221007141316_default_192.168.1.1_mit.kerberos.cca_155083.bin
[*] Auxiliary module execution completed
```

These creds can then be used in another module that uses Kerberos tickets.
