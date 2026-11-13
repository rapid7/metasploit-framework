## Vulnerable Application

Zimbra Collaboration Network Edition includes an Exchange Web Services (EWS)
extension for Outlook clients. CVE-2026-10631 is a confidentiality-only
authorization bypass in its `FindItem` handler. Affected servers trust the owner
UUID in a composite folder ID and run the folder read in that owner's
authorization context.

Zimbra 10.1.0 through 10.1.19 are affected. Zimbra 10.1.20 fixes the issue. The
[security advisory](https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories)
documents the version boundary.

An attacker needs credentials for an ordinary account in the deployment. The
EWS extension must be installed and `zimbraFeatureEwsEnabled` must be `TRUE` on
the attacker account or its class of service. The victim does not need EWS
enabled. `GetAccountInfoRequest` must permit the attacker to resolve the victim
address to its Zimbra account UUID.

To prepare an isolated lab:

1. Install a licensed Network Edition release in the affected range with its EWS
   extension and standard reverse proxy.
2. Create dedicated attacker and victim accounts with no share, mount point,
   delegation grant, or administrator relationship between them.
3. Enable EWS for the attacker account, for example as the `zimbra` user with
   `zmprov ma attacker@example.test zimbraFeatureEwsEnabled TRUE`.
4. Deliver benign, uniquely identifiable messages and attachments to the victim
   mailbox for `LIST` and `READ` validation.

No mailbox setup is required for `check`; a successful cross-account FindItem
against an empty folder is sufficient. To exclude legitimate access, the module
also requests the same folder with EWS `GetFolder`. It reports `Vulnerable` only
when `GetFolder` denies access but `FindItem` succeeds. If both operations
succeed, `check` returns `Detected` and an action does not create a CVE record.

## Verification Steps

1. Start Metasploit Framework from the source checkout.
2. Run: `use auxiliary/gather/zimbra_ews_mailbox_access`
3. Run: `set RHOSTS <target-host>`
4. Run: `set USERNAME <ews-enabled-account>`
5. Run: `set PASSWORD <account-password>`
6. Run: `set VICTIM <victim-address>`
7. Run: `check`
8. Run: `run`
9. Select `READ`, set `ITEM_ID` to an ID returned by `LIST`, and run again.

`check` first authenticates to ordinary Zimbra SOAP and performs an unqualified
FindItem against the attacker's own Inbox. It then requests the victim Inbox
with `GetFolder` to rule out a legitimate share or delegation. Only after that
operation denies access does it send victim FindItem with a composite folder
ID. `Vulnerable` therefore requires a structurally coherent FindItem response
after GetFolder denied access and is not based only on a version or endpoint
fingerprint.

The tested 10.1.16 GetFolder handler reports a code-less error while looking up
the effective ACL of an unshared foreign folder. The same identifier returns a
successful folder response after a read grant is added. The module accepts this
specific error as the no-grant control; unrelated code-less errors remain
unknown.

Every FindItem page must contain a valid non-negative reported total. An empty
page is coherent when that total is zero or the requested offset is past its
end. A page that omits the total, claims additional items but contains none, or
changes the total during one paginated operation stops that action so the
operator can rerun it against a stable mailbox view.

## Options

### USERNAME

Username of an ordinary account that can use EWS.

### PASSWORD

Password of the account in `USERNAME`.

### VICTIM

Address of the account whose mailbox will be read. The module resolves this
address with authenticated Zimbra SOAP and rejects an address that resolves to
the authenticated account.

### FOLDER

Numeric victim mailbox folder ID for both actions. The default is `2` (Inbox).
Other common IDs are `3` (Trash), `5` (Sent), `6` (Drafts), `7` (Contacts), and
`10` (Calendar).

### MAX_ITEMS

Maximum number of items to return for `LIST` or scan for `READ`. The default is
20 and the maximum is 10,000. Raise this when `ITEM_ID` is outside the newest
default window.

### PAGE_SIZE

Maximum number of items requested in each FindItem page. The default is 20 and
the maximum is 1,000. `READ` repeats only the page containing `ITEM_ID` with
MIME content enabled.

### ITEM_ID

Numeric victim item ID required by `READ`. Use an ID returned by `LIST` for the
same `FOLDER` and `VICTIM`.

### AutoCheck

Runs the behavioral authorization check before an action. Setting `AutoCheck`
to `false` skips that cross-mailbox gate, but the action still authenticates,
resolves both accounts, and proves that ordinary EWS works for the attacker.

### ForceExploit

Allows AutoCheck to continue after a `Safe` or `Unknown` result. It does not
override invalid action options, rejected credentials, or an unusable EWS
endpoint.

## Actions

### LIST

Lists items in the selected victim folder with paginated FindItem requests and
stores non-empty results as CSV loot. Returned IDs must have the resolved victim
UUID prefix. The sender column is read only from the EWS `From/Mailbox`
subtree, rather than from similarly named recipient fields.

### READ

Locates one numeric ID within the selected victim folder, repeats that FindItem
page with `IncludeMimeContent=true`, validates the exact returned ID, and saves
the base64-decoded message and its attachments as RFC 822 loot. This does not
use the separately authorized `GetItem` handler.

## Scenarios

### Zimbra 10.1.16 Network Edition on Ubuntu 22.04 x64 - LIST and READ

The isolated test system used a standard single-server HTTPS topology. This
redacted output was captured from the final source checkout.

```text
[*] Setting default action LIST - view all 2 actions with the show actions command
RHOSTS => 192.168.80.136
VHOST => mail.lab.local
USERNAME => attacker@lab.local
PASSWORD => <redacted>
VICTIM => victim@lab.local
MAX_ITEMS => 5
[+] 192.168.80.136:443 - The target is vulnerable. FindItem accessed victim@lab.local after GetFolder denied access on Zimbra 10.1.16
[*] Running module against 192.168.80.136
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. FindItem accessed victim@lab.local after GetFolder denied access on Zimbra 10.1.16
victim@lab.local - Inbox
========================

Item ID  Class     Read   From                               Subject
-------  -----     ----   ----                               -------
341      IPM.Note  false  qa@example.test <qa@example.test>  MSF-EWS-SCENARIO-20261104-B19C

[+] Stored 1 item entries in <loot-path>
[*] Auxiliary module execution completed
ACTION => READ
ITEM_ID => 341
[*] Running module against 192.168.80.136
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. FindItem accessed victim@lab.local after GetFolder denied access on Zimbra 10.1.16
[+] Stored victim message 341 and its attachments in <loot-path>
[*] Auxiliary module execution completed
```
