## Vulnerable Application

CVE-2026-73571 is an authorization failure in Zimbra Collaboration's
`SaveDraftRequest` SOAP handler. Its delegated-send path accepts an
attacker-selected local address as the owner of the From field, opens that
mailbox, and sends under an owner operation context without first requiring
`sendAs` or `sendOnBehalfOf`.

An ordinary authenticated user can therefore submit a message under another
local account's identity. The email follows Zimbra's ordinary MTA path and a
copy is written to that account's Sent folder. The attacker needs no victim
session, administrator privilege, delegation grant, or special account
feature.

The vulnerable path is known to affect Zimbra 10.1.16, was not present in the
original 10.1.0 release, and is fixed in 10.1.17. Its exact introduced release
is unknown. Technical details appear in
[Rapid7's Part One research](https://www.rapid7.com/blog/post/ve-breaking-zimbra-identity-boundaries-part-1/),
the [tracker writeup](https://github.com/jburgess-r7/zimbra-vulnerability-tracker/blob/main/vulnerabilities/CVE-2026-73571.md), and
the [vendor advisories](https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories).

Use dedicated attacker, selected-sender, and recipient accounts in a lab. They
must have no grant or administrator relationship. An existing legitimate
`sendAs` or `sendOnBehalfOf` grant would make the selected sender behavior
expected and invalid as vulnerability evidence.

`check` authenticates, resolves the selected local account, and reads the
Zimbra version. It does not deliver a message. Exact 10.1.16 builds return
`Appears`; 10.1.17 and later return `Safe`; versions between the confirmed
10.1.0 and 10.1.16 boundaries return `Detected` because the introduced release
has not been established.

## Verification Steps

1. Start Metasploit Framework from the source checkout.
2. Run: `use auxiliary/admin/http/zimbra_email_impersonation`
3. Run: `set RHOST <zimbra-host>`
4. Run: `set VHOST <zimbra-hostname>` when it differs from `RHOST`.
5. Set `USERNAME` and `PASSWORD` to an ordinary account.
6. Set `VICTIM` to a different local mailbox with no delegation grant to the
   attacker.
7. For end-to-end verification with no additional credential, set `RECIPIENT`
   to the same account as `USERNAME`.
8. Run: `check`
9. Run: `run`
10. Confirm the subject printed by the module is present in the attacker's Inbox
    with `VICTIM` as From and in `VICTIM`'s Sent folder.

To deliver to a different local recipient and retain automatic verification,
set `VERIFY_USERNAME` and `VERIFY_PASSWORD` to that recipient's credentials.
External recipients can be used without those options, but Metasploit cannot
inspect their resulting Inbox. In that case the accepted SOAP response is
reported as unverified, and the run creates no delivery-based vulnerability
record. Remove the uniquely marked verification message from the recipient
Inbox and selected account's Sent folder after isolated QA.

## Options

### USERNAME

Ordinary attacker account used for Zimbra SOAP authentication. It does not need
a delegation grant or licensed feature.

### PASSWORD

Password for `USERNAME`.

### VICTIM

Local account selected as the message From and impersonated sender. The module
resolves this account before delivery and rejects an address that resolves to
the authenticated user.

### RECIPIENT

Message recipient. Setting this to `USERNAME` enables automatic verification
with the attacker's existing token. Another local or external address can be
selected.

### SUBJECT

Email subject. Automatic Inbox verification appends a unique `[MSF-...]`
suffix so its search cannot match existing mail and the resulting artifacts can
be cleaned up exactly.

### BODY

Attacker-selected message content, up to 1 MiB.

### FORMAT

Selects a `text/plain` or `text/html` body.

### VERIFY_USERNAME and VERIFY_PASSWORD

Optional local `RECIPIENT` credentials used only for owner-authorized Inbox
verification. Supply both or neither. The module refuses to send if these
credentials resolve to a different account.

### VERIFY_TIMEOUT

Polling deadline in seconds for filtering and final mailbox delivery. The
default is 30 seconds. An in-flight SOAP request uses the inherited
`HttpClientTimeout` and can complete after this deadline.

### AutoCheck

Runs the non-mutating account and version check before delivering the message.
The default prevents accidental execution on a build known to contain the
10.1.17 fix. Framework can record a version-based `Appears` result before
delivery. A verified run attaches Inbox-delivery proof details to that
vulnerability; otherwise it remains version-only.

### ForceExploit

Allows execution after a `Safe` or `Unknown` AutoCheck result. Use this for a
controlled fixed-version test with automatic Inbox verification; the module
will report the sender it actually observes and will not create a vulnerability
record for a different effective sender.

## Scenarios

### Reconstructed Zimbra 10.1.16 Network Edition package set on Ubuntu 22.04 x64

This redacted transcript uses the attacker's own Inbox for end-to-end proof, so
the selected account's password is neither known nor supplied.

```text
msf auxiliary(admin/http/zimbra_email_impersonation) > check
[+] <target>:443 - Appears: Authenticated <attacker> and local target <selected-sender> are confirmed on known affected 10.1.16_GA_4850 20260106145110 20260106-1508 NETWORK

msf auxiliary(admin/http/zimbra_email_impersonation) > run
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Authenticated <attacker> and local target <selected-sender> are confirmed on known affected 10.1.16_GA_4850 20260106145110 20260106-1508 NETWORK
[*] Sending a delegated message from <selected-sender> to <attacker>
[*] Subject: Important message [MSF-<unique-marker>]
[+] Verified Inbox delivery from <selected-sender> to <attacker>
[*] Auxiliary module execution completed
```

The same affected build was also tested with separate recipient verification
credentials. The recipient Inbox showed the selected sender, while the exact
matching message appeared in that sender's Sent folder. Both plain and HTML
message formats passed. The database-backed run recorded one `zimbra-soap`
service, one successful ordinary-account login, and the verified vulnerability.
