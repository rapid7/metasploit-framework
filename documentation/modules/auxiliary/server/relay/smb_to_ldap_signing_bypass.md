## Vulnerable Application

CVE-2026-70229 is an LDAP reauthentication flaw in Active Directory domain
controllers. A signed LDAP SASL record can contain multiple LDAP messages. On
affected DCs, reauthentication changes the authorization identity before the
remaining messages in that record are executed, but the entire record was
already verified with the bootstrap identity's known NTLM key.

Windows Server 2016 through Windows
Server 2025 DCs were affected before the October 2026 cumulative updates. Its
Server 2025 test used build 26100.33451; the fix was introduced in build
26100.33648 by KB5126646. Install the applicable October 2026 or later
cumulative update for each deployed Windows Server release.

The module requires all of the following:

- Plaintext LDAP transport to TCP/389. The LDAP messages are signed and sealed
  by NTLM SASL; LDAPS and StartTLS are not supported by this technique.
- An SMB client that authenticates with NTLM and requests NTLM signing. The
  module does not remove the MIC or NTLM signing, sealing, or key-exchange
  flags.
- A bootstrap SASL identity. `ANONYMOUS` explicitly attempts anonymous NTLM
  SASL. This succeeds only on DCs that support that context. `NTLM` uses the
  configured `LDAPDomain`, `LDAPUsername`, and `LDAPPassword`.
- A target account or distinguished name. Account names must be searchable by
  the bootstrap identity. A direct DN avoids that name lookup.
- For RBCD, an existing controlled account or its SID and permission for the
  bootstrap identity to read the target's current
  `msDS-AllowedToActOnBehalfOfOtherIdentity`. A direct DN and SID do not bypass
  this read prerequisite.
- For shadow credentials, Active Directory Certificate Services and PKINIT
  support must be available for later certificate authentication. The
  bootstrap identity does not need permission to read existing key
  credentials because the module uses an LDAP ADD rather than replacing the
  attribute.

Bootstrap credentials authenticate only the initial signed SASL connection.
The identity relayed from SMB supplies the authorization for the LDAP
modification.

The module performs no coercion. It also creates no LDAP session, acquires no
Kerberos ticket, and performs no command execution. The result is only the
configured directory attribute change.

## Verification Steps

1. Build an authorized lab with two domain-joined Windows systems: an affected
   DC and an SMB client identity that has write permission for the selected
   directory attribute.
1. Configure the DC to require LDAP signing.
1. Create or select an existing controlled account for RBCD, and record its
   SID if anonymous directory searches will be restricted.
1. Start Metasploit Framework.
1. Run `use auxiliary/server/relay/smb_to_ldap_signing_bypass`.
1. Configure `RHOSTS` with the DC address and `TARGET_ACCOUNT` with an explicit
   sAMAccountName or DN.
1. For RBCD, configure `DELEGATE_FROM` with the controlled account or its SID.
1. If anonymous NTLM SASL is unsupported, set `BOOTSTRAP_AUTH NTLM` and set
   `LDAPDomain`, `LDAPUsername`, and `LDAPPassword`.
1. Run the module and separately cause the authorized SMB client to
   authenticate to the module's listener.
1. Confirm the exact ACE or device ID with a fresh LDAP connection.

The module suppresses a repeat for a confirmed or uncertain write. Stop and
restart the job only after investigating an uncertain result; a disconnect
alone neither confirms the write nor establishes that the target is patched.

## Options

### ACTION

`RBCD` adds one ACE to the existing
`msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor and preserves
all established existing data. `SHADOW_CREDENTIALS` generates a certificate
and adds one `msDS-KeyCredentialLink` value without replacing current values.
The default is `RBCD`.

RBCD uses a read-modify-replace operation prepared before the victim's final
authentication exchange. It preserves the descriptor observed during that
read, but a concurrent update made after preparation and before replacement
can be overwritten. Avoid other RBCD changes while an attempt is active, and
retain the stored original descriptor for recovery.

### BOOTSTRAP_AUTH

`ANONYMOUS` attempts only anonymous NTLM SASL. `NTLM` uses only the three LDAP
credential options. There is no automatic fallback between modes. The default
is `ANONYMOUS`.

### LDAPDomain, LDAPUsername, LDAPPassword

Credentials used when `BOOTSTRAP_AUTH` is `NTLM`. They establish the initial
signed context and perform required lookups and read-back verification.

### TARGET_ACCOUNT

Required sAMAccountName or full LDAP distinguished name to modify. This is not
implicitly derived from the relayed identity. Use a direct DN if the bootstrap
identity cannot search the directory.

### DELEGATE_FROM

For `RBCD`, the existing controlled sAMAccountName whose SID is added to the
descriptor. A direct SID is accepted when directory searches are unavailable.
The module never creates an account.

### BASE_DN

Optional directory search base. The module attempts to discover
`defaultNamingContext` over the bootstrap context when this is unset. It is
not needed when every input is a DN or SID, except that RBCD still requires a
successful base-object read of the current descriptor.

### RHOSTS and RPORT

LDAP targets and plaintext LDAP port. The default port is 389. Port 636 is
rejected because LDAPS does not provide the identity-owned SASL security layer
used by this technique.

## Result Interpretation

The module tracks victim authentication and directory modification separately.
A successful bind does not imply that the write ran. A successful LDAP modify
response or a fresh bootstrap-authenticated read-back confirms completion.
When neither is available, the write is reported as unconfirmed and is not
automatically replayed. Incorrect bootstrap credentials, denied lookups,
victim authentication rejection, and insufficient write privileges are
reported at their respective stages.

## Recovery

For RBCD, the original binary security descriptor is stored as loot before it
is replaced. Recovery should remove only the ACE for the reported
`DELEGATE_FROM` SID. If exact restoration is needed, use the stored original
descriptor with an authorized LDAP client; if the attribute was previously
absent, remove the attribute after confirming it contains only the added ACE.

For shadow credentials, the PKCS#12 certificate and private key are persisted
before the write. The exact DN-Binary value is saved separately as recovery
loot. The PKCS#12 password is empty. Remove only the reported device ID or that exact value. Existing key
credentials are not replaced. Keep the generated material until an uncertain
result has been investigated.

## Scenarios
All testing was preformed on 