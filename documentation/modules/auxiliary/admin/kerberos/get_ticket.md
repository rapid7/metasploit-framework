## Requesting tickets 

The `auxiliary/admin/kerberos/get_ticket` module can be used to request TGT/TGS tickets from the KDC.

The following ACTIONS are supported:

- **GET_TGT**: legally request a TGT from the KDC given a password, a NT hash or
  an encryption key. The resulting TGT will be cached.
- **GET_TGS**: legally request a TGS from the KDC given a password, a NT hash, an
  encryption key or a cached TGT. If the TGT is not provided, it will request
  it the same way the "TGT action" does. The resulting TGT and the TGS will be
  cached.

## Module usage

- Start `msfconsole`
- Do: `use auxiliary/admin/kerberos/get_ticket`
- Do: `run rhosts=<remote host> domain=<domain> username=<username> password=<password> action=GET_TGT`
- You should see that the TGT is correctly retrieved and stored in loot as well as the klist command
- Try with the NT hash (`NTHASH` option) and the encryption key (`AES_KEY`
  option) instead of the password
- Do: `run rhosts=<remote host> domain=<domain> username=<username> password=<password> action=GET_TGS spn=<SPN>`
- You should see that the module uses the TGT in the cache and does not request a new one
- You should see TGS is correctly retrieved and stored in the loot
- Do: `run rhosts=<remote host> domain=<domain> username=<username> password=<password> action=GET_TGS spn=<SPN> KrbUseCachedCredentials=false`
- You should see the module does not use the TGT in the cache and requests a new one
- You should see both the TGT and the TGS are correctly retrieved and stored in the loot
- Try with the NT hash (`NTHASH` option) and the encryption key (`AES_KEY` option) instead of the password

## Options

### CERT_FILE
The PKCS12 (.pfx) certificate file to authenticate with. When this option is set, USERNAME and DOMAIN are optional and
will be extracted from the certificate unless specified. Specifying a certificate causes PKINIT to be used to obtain the
ticket. The module will provide a warning if USERNAME and DOMAIN are set but do not match any entries within the
certificate.

### CERT_PASSWORD
The certificate file's password.

### DOMAIN
The Fully Qualified Domain Name (FQDN). Ex: mydomain.local

### USERNAME
The domain username to authenticate with.

### PASSWORD
The user's password to use.

### NTHASH
The user's NT hash in hex string to authenticate with. Not that the DC must
support RC4 encryption.

### AES_KEY
The user's AES key to use for Kerberos authentication in hex string. Supported
keys: 128 or 256 bits.

### SPN
The Service Principal Name, the format is `service_name/FQDN` . Ex:
cifs/dc01.mydomain.local. This option is only used when requesting a TGS.

### IMPERSONATE
The user on whose behalf a TGS is requested (it will use S4U2Self/S4U2Proxy to
request the ticket).

### KrbUseCachedCredentials
If set to `true`, it looks for a matching TGT in the database and, if found,
use it for Kerberos authentication when requesting a TGS. Note that this option
only applies to `GET_TGS` action and has no effect on the `GET_TGT` action.
Default is `true`.

## Scenarios

### Requesting a TGT

An example of viewing the Kerberos ticket cache, and requesting a TGT with NT hash:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > klist
Kerberos Cache
==============
No tickets

msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator nthash=<redacted> action=GET_TGT
[*] Running module against 10.0.0.24

[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104181416_default_10.0.0.24_mit.kerberos.cca_912121.bin
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) > klist
Kerberos Cache
==============
host            principal                 sname                         issued                     status  path
----            ---------                 -----                         ------                     ------  ----
192.168.123.13  Administrator@ADF3.LOCAL  krbtgt/ADF3.LOCAL@ADF3.LOCAL  2023-01-12 19:37:54 +0000  valid   /Users/usr/.msf4/loot/20230112193756_default_192.168.123.13_mit.kerberos.cca_131390.bin
 
msf6 auxiliary(admin/kerberos/get_ticket) > hosts

Hosts
=====

address          mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------          ---  ----  -------  ---------  -----  -------  ----  --------
10.0.0.24                   Unknown                    device

msf6 auxiliary(admin/kerberos/get_ticket) > services
Services
========

host             port  proto  name      state  info
----             ----  -----  ----      -----  ----
10.0.0.24        88    tcp    kerberos  open   Module: auxiliary/admin/kerberos/get_ticket, KDC for domain mylab.local
```

TGT with encryption key

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator AES_KEY=<redacted> action=GET_TGT
[*] Running module against 10.0.0.24

[*] 10.0.0.24:88 - Getting TGT for Administrator@mylab.local
[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104182051_default_10.0.0.24_mit.kerberos.cca_535003.bin
[*] Auxiliary module execution completed
```

TGT with password

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator password=<redacted> action=GET_TGT
[*] Running module against 10.0.0.24

[*] 10.0.0.24:88 - Getting TGT for Administrator@mylab.local
[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104182219_default_10.0.0.24_mit.kerberos.cca_533360.bin
[*] Auxiliary module execution completed
```

TGT with certificate

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 cert_file=/home/msfuser/.msf4/loot/20230124155521_default_10.0.0.24_windows.ad.cs_384669.pfx action=GET_TGT
[*] Running module against 10.0.0.24

[*] 10.0.0.24:88 - Getting TGT for Administrator@mylab.local
[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache ticket saved to /home/msfuser/.msf4/loot/20230124155555_default_192.168.159.10_mit.kerberos.cca_702818.bin
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) >
```

### Requesting a TGS

TGS with NT hash:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator nthash=<redacted> action=GET_TGS spn=cifs/dc02.mylab.local
[*] Running module against 10.0.0.24

[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104182601_default_10.0.0.24_mit.kerberos.cca_760650.bin
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221104182601_default_10.0.0.24_mit.kerberos.cca_883314.bin
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) > loot

Loot
====

host             service  type                 name  content                   info                                                                             path
----             -------  ----                 ----  -------                   ----                                                                             ----
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: administrator     /home/msfuser/.msf4/loot/20221104182601_default_10.0.0.24_mit.kerberos.cca_760650.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221104182601_default_10.0.0.24_mit.kerberos.cca_883314.bin
```

TGS with encryption key:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator AES_KEY=<redacted> action=GET_TGS spn=cifs/dc02.mylab.local
[*] Running module against 10.0.0.24

[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104183040_default_10.0.0.24_mit.kerberos.cca_140502.bin
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221104183040_default_10.0.0.24_mit.kerberos.cca_500387.bin
[*] Auxiliary module execution completed
```

TGS with password:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator password=<redacted> action=GET_TGS spn=cifs/dc02.mylab.local
[*] Running module against 10.0.0.24

[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_171694.bin
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_360960.bin
[*] Auxiliary module execution completed
```

TGS with cached TGT:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > loot

Loot
====

host             service  type                 name  content                   info                                                                             path
----             -------  ----                 ----  -------                   ----                                                                             ----
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: administrator     /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_171694.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_360960.bin

msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator action=GET_TGS spn=cifs/dc02.mylab.local
[*] Running module against 10.0.0.24

[*] 10.0.0.24:88 - Using cached credential for krbtgt/mylab.local Administrator
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221104183346_default_10.0.0.24_mit.kerberos.cca_525186.bin
[*] Auxiliary module execution completed
```

TGS without cached TGT:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > loot

Loot
====

host             service  type                 name  content                   info                                                                             path
----             -------  ----                 ----  -------                   ----                                                                             ----
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: administrator     /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_171694.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_360960.bin

msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator action=GET_TGS spn=cifs/dc02.mylab.local KrbUseCachedCredentials=false
[*] Running module against 10.0.0.24

[-] Auxiliary aborted due to failure: unknown: Error while requesting a TGT: Kerberos Error - KDC_ERR_PREAUTH_REQUIRED (25) - Additional pre-authentication required - Check the authentication-related options (PASSWORD, NTHASH or AES_KEY)
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=Administrator action=GET_TGS spn=cifs/dc02.mylab.local KrbUseCachedCredentials=false password=<redacted>
[*] Running module against 10.0.0.24

[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved on /home/msfuser/.msf4/loot/20221104183538_default_10.0.0.24_mit.kerberos.cca_200958.bin
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221104183538_default_10.0.0.24_mit.kerberos.cca_849639.bin
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) > loot

Loot
====

host             service  type                 name  content                   info                                                                             path
----             -------  ----                 ----  -------                   ----                                                                             ----
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: administrator     /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_171694.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221104183244_default_10.0.0.24_mit.kerberos.cca_360960.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: administrator     /home/msfuser/.msf4/loot/20221104183538_default_10.0.0.24_mit.kerberos.cca_200958.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221104183538_default_10.0.0.24_mit.kerberos.cca_849639.bin
```

TGS impersonating the Administrator account:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run verbose=true rhosts=10.0.0.24 domain=mylab.local username=serviceA password=123456 action=GET_TGS spn=cifs/dc02.mylab.local impersonate=Administrator
[*] Running module against 10.0.0.24

[*] 10.0.0.24:88 - Getting TGS impersonating Administrator@mylab.local (SPN: cifs/dc02.mylab.local)
[+] 10.0.0.24:88 - Received a valid TGT-Response
[*] 10.0.0.24:88 - TGT MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221201210211_default_10.0.0.24_mit.kerberos.cca_667626.bin
[+] 10.0.0.24:88 - Received a valid TGS-Response
[+] 10.0.0.24:88 - Received a valid TGS-Response
[*] 10.0.0.24:88 - TGS MIT Credential Cache saved to /home/msfuser/.msf4/loot/20221201210211_default_10.0.0.24_mit.kerberos.cca_757041.bin
[*] Auxiliary module execution completed
msf6 auxiliary(admin/kerberos/get_ticket) > loot

Loot
====

host             service  type                 name  content                   info                                                                             path
----             -------  ----                 ----  -------                   ----                                                                             ----
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: krbtgt/mylab.local, username: servicea          /home/msfuser/.msf4/loot/20221201210211_default_10.0.0.24_mit.kerberos.cca_667626.bin
10.0.0.24                 mit.kerberos.ccache        application/octet-stream  realm: MYLAB.LOCAL, serviceName: cifs/dc02.mylab.local, username: administrator  /home/msfuser/.msf4/loot/20221201210211_default_10.0.0.24_mit.kerberos.cca_757041.bin
```
