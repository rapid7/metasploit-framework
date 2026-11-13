## Vulnerable Application

Zimbra Collaboration Network Edition 10.1.0 through 10.1.21 is affected when
the Network Edition GraphQL extension is installed and the endpoint at
`/service/extension/graphql` is reachable. No fixed release has been published.

The unauthenticated `authenticate` mutation invokes Zimbra's authentication
handler without marking the servlet request as a failed login. The surrounding
`ZimbraInvalidLoginFilter` consequently does not increment its source-IP
counter. A request can also use GraphQL aliases to run many independent
authentication operations.

Per-account lockout is a separate control. When
`zimbraPasswordLockoutEnabled` is `TRUE`, wrong attempts can lock an existing
local account. Zimbra does not distinguish a locked account from a rejected
password in this response. Some external-LDAP failures use the same response.
Account lockout is disabled by default.

Large GraphQL documents can consume Zimbra request threads or enter recursive
error handling. The default batch size is 50. The useful limit is
deployment-dependent; `BATCH_SIZE` values greater than 100 cause a warning and
should be used with care.

To reproduce the source-IP limiter, preserve the appliance's
`zimbraMailTrustedIP` reverse-proxy trust. A manual package installation that
omits it leaves the filter without the originating IP and prevents normal SOAP
failures from reaching the source counter.

The live test target used archived Zimbra 10.1.16 Network Edition packages
manually installed on a 10.1.0 base image.

The `check` command submitted two aliases for one randomly generated,
nonexistent account and received two independent authentication failures in one
HTTP response. That limited probe reports `Detected`: it confirms the
GraphQL capability but does not measure source-IP failure-counter accounting.

## Verification Steps

1. Start `msfconsole`.
1. Run `use auxiliary/scanner/http/zimbra_graphql_brute`.
1. Run `set RHOSTS <target>`.
1. Run `check`.
1. Run `set USERNAME <target-account>`.
1. Run `set PASS_FILE <candidate-file>`.
1. Run `run`.
1. Confirm that a matching candidate is stored as a credential without the
   returned authentication token being displayed.

`run` begins with the same two-alias preflight used by `check`. This identifies
the GraphQL behavior before any supplied credential is sent, but does not create
a CVE vulnerability record because it does not exercise the configured
source-IP threshold. Accepted passwords are still stored as credentials.

## Options

### BATCH_SIZE

The number of aliased GraphQL `authenticate` mutations sent in one HTTP
request. The default is 50 and the allowed range is 1 through 1,000. Lower
values reduce per-request load. A value of 1 uses the same authentication path
without alias multiplication.

`BATCH_SIZE` must be 1 when `STOP_ON_SUCCESS` is enabled or
`MaxGuessesPerService` is nonzero. This lets the module stop before sending the
next candidate and keeps skipped, already-successful users out of the guess
count. It must also be 1 when `TRANSITION_DELAY` is enabled; otherwise
candidates from password or username transitions would be held and transmitted
together.

The inherited `BRUTEFORCE_SPEED` delay is applied between HTTP requests rather
than between aliases in one already-constructed request.

## Scenarios

### Zimbra 10.1.16 Network Edition on Ubuntu 22.04 x64

The following console output was recorded against a licensed 10.1.16 Network
Edition VM. Account and host values have been replaced with reserved example
names.

The first run used the default `BATCH_SIZE` of 50 and a `USERPASS_FILE` containing
49 candidates for a nonexistent account followed by one known-valid account.
`STOP_ON_SUCCESS` was `false` and `MaxGuessesPerService` was `0`.

```text
[*] 192.0.2.10:443 - The service is running, but could not be validated. Two aliased GraphQL authenticate operations ran in one unauthenticated HTTP request
[+] 192.0.2.10:443    - [50/50] - Valid credential found for researcher@example.invalid
[+] Submitted 50 credential candidate(s) in 1 GraphQL request(s); found 1 valid credential(s)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

A second word-pair file contained a valid password for the first account, an
invalid password for that same account, and a valid password for a second
account. With `BATCH_SIZE=1` and `STOP_ON_SUCCESS=true`, only the first candidate
was submitted:

```text
[+] 192.0.2.10:443    - [1/3] - Valid credential found for researcher@example.invalid
[+] Submitted 1 credential candidate(s) in 1 GraphQL request(s); found 1 valid credential(s)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

With `STOP_ON_SUCCESS=false` and `MaxGuessesPerService=2`, the same file reached
the second account without counting the skipped password as an attempt:

```text
[+] 192.0.2.10:443    - [1/2] - Valid credential found for researcher@example.invalid
[+] 192.0.2.10:443    - [2/2] - Valid credential found for colleague@example.invalid
[+] Submitted 2 credential candidate(s) in 2 GraphQL request(s); found 2 valid credential(s)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Separate requests remain outside the source-IP counter

An earlier control test used a source-IP maximum of 10. With reverse-proxy trust active,
ordinary SOAP requests 1 through 11 returned authentication faults and
requests 12 and 13 returned HTTP 503. With `BATCH_SIZE` set to 1, GraphQL
processed eleven rejected passwords in eleven HTTP requests, then accepted
the known-valid laboratory credential on request 12:

```text
[*] Submitted 11 credential candidate(s) in 11 GraphQL request(s); no accepted credential was returned
[+] 192.0.2.10:443 - Valid credential found for researcher@example.invalid
[+] Submitted 1 credential candidate(s) in 1 GraphQL request(s); found 1 valid credential(s)
```
