## Vulnerable Application

KerberLoss (CVE-2026-25177) is an Active Directory SPN comparison inconsistency. Active Directory stores some
invisible Unicode characters in `servicePrincipalName`, but its LDAP comparison path ignores those characters.
On affected domain controllers, this can bypass SPN and SPN-alias uniqueness checks.

An operator who has unrestricted `WriteProperty` or equivalent control over another account's
`servicePrincipalName` can add a value such as `cifs/DC1.example.test<U+200C>`. A request for the clean
`cifs/DC1.example.test` value can then resolve to the modified account. The KDC can issue a service ticket encrypted
with that account's key instead of the intended service account's key. A collision with an explicitly registered SPN
can instead cause `KDC_ERR_S_PRINCIPAL_UNKNOWN`, leading to authentication failure or NTLM fallback.

Microsoft fixed CVE-2026-25177 on March 10, 2026. Test only domain controllers that are deliberately unpatched and
isolated. This module was tested against Windows Server 2019 Datacenter Evaluation build `17763.3650` in an isolated
lab with no default gateway.

The required permission is important. `Validated-Write-SPN`, including the right held by a machine account over
itself, validates the hostname and normally cannot claim a foreign service identity. A `constraintViolation` can mean
either that the DC is patched or that the operator has only the validated write primitive. It does not distinguish
those cases by itself.

### Lab setup

1. Install a pre-March-2026 Windows Server build in an isolated virtual network.
1. Promote the server to a domain controller for a test forest.
1. Create a low-privilege operator account and a separate target account.
1. Give the operator unrestricted write permission on the target account's `servicePrincipalName` property. Do not
   use `Validated-Write-SPN` for this test.
1. Give the attacker VM network access only to the isolated domain controller.
1. Record every SPN present on the target account before testing so the original state can be verified afterward.

## Actions

### AUDIT

Reads the target account's explicit SPNs and queries the current owners of `SPN`. This is the default and does not
modify Active Directory.

### CHECK

Adds a random `msf/<random>.invalid` SPN with the selected codepoint, queries its clean form, and removes the exact
value in an `ensure` block. A successful LDAP match means the DC appears to have the vulnerable comparison behavior.
This action does not prove KDC ticket-key ownership.

### HIJACK

Adds `SPN` plus `UNICODE_CODEPOINT` to the target account and classifies the resulting LDAP resolution as a hijack,
collision, or ineffective write. A collision is only reported when the target account becomes a new owner of the clean
SPN, so a name that already had several owners is not mistaken for a successful write. An ineffective write is rolled
back automatically, as is a write whose verification query fails. A successful hijack or collision is left in place
for authorized testing and must be removed with `CLEANUP`.

The module refuses to overwrite or later roll back an identical hidden-character SPN that was already present.

### CLEANUP

Removes the exact value produced from `SPN` and `UNICODE_CODEPOINT`. The action is idempotent: it reads the target's
SPNs first and does nothing when that exact value is absent. Because the module cannot tell a value it wrote from an
identical value that was already there, it warns before the delete. Compare the value against the baseline recorded
during lab setup before confirming the removal.

## Verification Steps

1. Start `msfconsole` from a current Metasploit Framework checkout.
1. Run `use auxiliary/admin/ldap/kerberloss`.
1. Set `RHOSTS`, `LDAPDomain`, `LDAPUsername`, and `LDAPPassword` for the isolated DC.
1. Set either `TARGET_DN` or `TARGET_ACCOUNT`.
1. Set `SPN` to the clean service identity to test.
1. Run the default `AUDIT` action and record the baseline.
1. Set `ACTION CHECK` and run the module. Confirm a second `AUDIT` shows no random probe SPN.
1. Set `ACTION HIJACK` and run the module.
1. Independently request a TGS for the clean SPN and verify that its encrypted ticket part decrypts with the target
   account's long-term key. LDAP resolution alone is not cryptographic proof.
1. Set `ACTION CLEANUP` and run the module.
1. Run `AUDIT` again and confirm the target's SPNs match the recorded baseline.

## Options

### BASE_DN

The LDAP base DN. The module discovers it automatically when omitted.

### TARGET_DN

The distinguished name of the account that receives the test SPN. Set either this option or `TARGET_ACCOUNT`.

### TARGET_ACCOUNT

The `sAMAccountName` of the account that receives the test SPN. Set either this option or `TARGET_DN`.

### SPN

The clean service principal name to query or influence, for example `cifs/DC1.example.test`. This option is required
for `AUDIT`, `HIJACK`, and `CLEANUP`. `CHECK` generates a random probe instead.

Use the exact hostname clients put in the TGS request. Short-name and fully qualified SPNs are different values.

Supply the clean value only. The module rejects an `SPN` that already carries a comparison-ignorable codepoint,
because every clean-SPN query it runs would otherwise be a query for a poisoned value.

### UNICODE_CODEPOINT

The codepoint appended to `SPN`. The default is `U+200C`. The values observed as comparison-ignorable in the tested
Server 2019 lab are `U+00AD`, `U+034F`, `U+061C`, `U+200C`, `U+200D`, `U+2060`, and `U+FEFF`.

`U+200B` is included as a negative control because it remained literal on the tested build. Unicode comparison tables
can vary between Windows versions, so use `CHECK` before a stateful action.

## Scenarios

### Windows Server 2019 Datacenter Evaluation build 17763.3650

The isolated lab used `kerberloss.test`, DC `192.0.2.10`, operator `kloperator`, and target DN
`CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test`.

Baseline audit:

```
msf auxiliary(admin/ldap/kerberloss) > run
[*] Running module against 192.0.2.10
[*] Target: CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test
[*] Target SPN: HTTP/kltarget.kerberloss.test
[*] Exact-query owners of cifs/DC1.kerberloss.test: none
[*] Auxiliary module execution completed
```

Reversible comparison check:

```
msf auxiliary(admin/ldap/kerberloss) > set ACTION CHECK
ACTION => CHECK
msf auxiliary(admin/ldap/kerberloss) > run
[*] Running module against 192.0.2.10
[*] Testing comparison behavior with temporary value msf/x1ftvvqs0cb2ywfc.invalid<U+200C>
[+] The clean probe resolved to the account containing the hidden-character SPN; the DC appears affected.
[*] Auxiliary module execution completed
```

Service-SPN hijack:

```
msf auxiliary(admin/ldap/kerberloss) > set ACTION HIJACK
ACTION => HIJACK
msf auxiliary(admin/ldap/kerberloss) > run
[*] Running module against 192.0.2.10
[*] Adding cifs/DC1.kerberloss.test<U+200C> to CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test
[+] The clean SPN now resolves to the target account in LDAP: CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test
[!] Request and decrypt a service ticket before treating LDAP resolution as cryptographic proof.
[*] Auxiliary module execution completed
```

In this lab, an independent TGS verifier requested `cifs/DC1.kerberloss.test`. The KDC returned encryption type 23,
and the encrypted ticket part decrypted with the `KLTarget` account's RC4-HMAC key. That supplied the cryptographic
proof that the clean service identity had been redirected to the target account.

Cleanup and baseline restoration:

```
msf auxiliary(admin/ldap/kerberloss) > set ACTION CLEANUP
ACTION => CLEANUP
msf auxiliary(admin/ldap/kerberloss) > run
[*] Running module against 192.0.2.10
[*] Removing cifs/DC1.kerberloss.test<U+200C> from CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test
[+] The exact hidden-character SPN was removed.
[*] Auxiliary module execution completed
```

A final `AUDIT` showed only `HTTP/kltarget.kerberloss.test`, and the clean CIFS SPN again had no explicit LDAP owner.
