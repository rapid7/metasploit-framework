The kerberos_enumusers module is used to enumerate valid Domain Users
via Kerberos from a wholly unauthenticated perspective. It utilises the
different responses returned by the service to identify users that exist
within the target domain. It is also able to identify whether user
accounts are enabled or disabled/locked out.

## Target

To use kerberos_enumusers, make sure you are able to connect to the
Kerberos service on a Domain Controller.

## Scenario

The following demonstrates basic usage, using a custom wordlist,
targeting a single Domain Controller to identify valid domain user
accounts.

```
msf > use auxiliary/gather/kerberos_enumusers
msf auxiliary(kerberos_enumusers) > set DOMAIN MYDOMAIN
DOMAIN => MYDOMAIN
msf auxiliary(kerberos_enumusers) > set RHOST 192.168.5.1
RHOST => 192.168.5.1
msf auxiliary(kerberos_enumusers) > set USER_FILE /job/users.txt
USER_FILE => /job/users.txt
msf auxiliary(kerberos_enumusers) > run

[*] Validating options...
[*] Using domain: MYDOMAIN...
[*] 192.168.5.1:88 - Testing User: "bob"...
[*] 192.168.5.1:88 - KDC_ERR_PREAUTH_REQUIRED - Additional
pre-authentication required
[+] 192.168.5.1:88 - User: "bob" is present
[*] 192.168.5.1:88 - Testing User: "alice"...
[*] 192.168.5.1:88 - KDC_ERR_PREAUTH_REQUIRED - Additional
pre-authentication required
[+] 192.168.5.1:88 - User: "alice" is present
[*] 192.168.5.1:88 - Testing User: "matt"...
[*] 192.168.5.1:88 - KDC_ERR_PREAUTH_REQUIRED - Additional
pre-authentication required
[+] 192.168.5.1:88 - User: "matt" is present
[*] 192.168.5.1:88 - Testing User: "guest"...
[*] 192.168.5.1:88 - KDC_ERR_CLIENT_REVOKED - Clients credentials have
been revoked
[-] 192.168.5.1:88 - User: "guest" account disabled or locked out
[*] 192.168.5.1:88 - Testing User: "admint"...
[*] 192.168.5.1:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in
Kerberos database
[*] 192.168.5.1:88 - User: "admint" does not exist
[*] 192.168.5.1:88 - Testing User: "admin"...
[*] 192.168.5.1:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in
Kerberos database
[*] 192.168.5.1:88 - User: "admin" does not exist
[*] 192.168.5.1:88 - Testing User: "administrator"...
[*] 192.168.5.1:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in
Kerberos database
[*] 192.168.5.1:88 - User: "administrator" does not exist
[*] Auxiliary module execution completed
msf auxiliary(kerberos_enumusers) >
```

## Options

The kerberos_enumusers module only requires the RHOST, DOMAIN and
USER_FILE options to run.

**The DOMAIN option**

This option is used to specify the target domain. If the domain name is
incorrect an error is returned and domain user account enumeration will fail.

An example of setting DOMAIN:

```
set DOMAIN [domain name]
```

**The USER_FILE option**

This option is used to specify the file containing a list of user names
to query the Domain Controller to identify if they exist in the target domain
or not. One per line.

An example of setting USER_FILE:

```
set USER_FILE [path to file]
```

**The Timeout option**

This option is used to specify the TCP timeout i.e. the time to wait
before a connection to the Domain Controller is established and data read.

An example of setting Timeout:

```
set Timeout [value in seconds]
```
