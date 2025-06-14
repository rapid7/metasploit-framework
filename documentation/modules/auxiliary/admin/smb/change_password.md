## Introduction

Allows changing or resetting users' passwords.

"Changing" refers to situations where you know the value of the existing password, and send that to the server as part of the password modification.
"Resetting" refers to situations where you may not know the value of the existing password, but by virtue of your permissions over the target account, you can force-change the password without necessarily knowing it.

Note that users can typically not reset their own passwords (unless they have very high privileges).

This module works with existing sessions (or relaying), especially for Reset use cases, wherein the target's password is not required.

## Actions

- `RESET` - Reset the target's password without knowing the existing one (requires appropriate permissions). New AES kerberos keys will be generated.
- `RESET_NTLM` - Reset the target's NTLM hash, without knowing the existing password. AES kerberos authentication will not work until a standard password change occurs.
- `CHANGE` - Change the password, knowing the existing one. New AES kerberos keys will be generated.
- `CHANGE_NTLM` - Change the password to a NTLM hash value, knowing the existing password. AES kerberos authentication will not work until a standard password change occurs.

## Options

The required options are based on the action being performed:

- When resetting a password, you must specify the `TARGET_USER`
- When changing a password, you must specify the `SMBUser` and `SMBPass`, even if using an existing session (since the API requires both of these to be specified, even for open SMB sessions)
- When resetting or changing a password, you must specify `NEW_PASSWORD`
- When resetting or changing an NTLM hash, you must specify `NEW_NTLM`

**SMBUser**

The username to use to authenticate to the server. Required for changing a password, even if using an existing session.

**SMBPass**

The password to use to authenticate to the server, prior to performing the password modification. Required for changing a password, even if using an existing session (since the server requires proof that you know the existing password).

**TARGET_USER**

For resetting passwords, the user account for which to reset the password. The authenticated account (SMBUser) must have privileges over the target user (e.g. Ownership, or the `User-Force-Change-Password` extended right)

**NEW_PASSWORD**

The new password to set for `RESET` and `CHANGE` actions. 

**NEW_NTLM**

The new NTLM hash to set for `RESET_NTLM` and `CHANGE_NTLM` actions. This can either be an NT hash, or a colon-delimited NTLM hash.