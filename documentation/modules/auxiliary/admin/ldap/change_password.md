## Introduction

Allows changing or resetting users' passwords over the LDAP protocol (particularly for Active Directory).

"Changing" refers to situations where you know the value of the existing password, and send that to the server as part of the password modification.
"Resetting" refers to situations where you may not know the value of the existing password, but by virtue of your permissions over the target account, you can force-change the password without necessarily knowing it.

Note that users can typically not reset their own passwords (unless they have very high privileges), but can usually change their password as long as they know the existing one.

This module works with existing sessions (or relaying), especially for resetting, wherein the target's password is not required.

## Actions

- `RESET` - Reset the target's password without knowing the existing one (requires appropriate permissions)
- `CHANGE` - Change the user's password, knowing the existing one.

## Options

The required options are based on the action being performed:

- When resetting a password, you must specify the `TARGET_USER`
- When changing a password, you must specify the `LDAPUsername` and `LDAPPassword`, even if using an existing session (since the API requires both of these to be specified, even for open LDAP sessions)
- The `NEW_PASSWORD` option must always be provided

**LDAPUsername**

The username to use to authenticate to the server. Required for changing a password, even if using an existing session.

**LDAPPassword**

The password to use to authenticate to the server, prior to performing the password modification. Required for changing a password, even if using an existing session (since the server requires proof that you know the existing password).

**TARGET_USER**

For resetting passwords, the user account for which to reset the password. The authenticated account (username) must have privileges over the target user (e.g. Ownership, or the `User-Force-Change-Password` extended right)

**NEW_PASSWORD**

The new password to set.