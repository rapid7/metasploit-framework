## Vulnerable Application

CVE-2026-73571 is an authorization failure in Zimbra Collaboration's
`SaveDraftRequest` SOAP handler. Its delegated-send path accepts an
attacker-selected local address as the owner of the From field, opens that
mailbox, and sends under an owner operation context without first requiring
`sendAs` or `sendOnBehalfOf`.

An ordinary authenticated user can submit a message under another account's identity when both use the same mailbox server.
The email follows Zimbra's ordinary MTA path and a copy is written to that account's Sent folder.
The attacker needs no victim session, administrator privilege, delegation grant, or special account feature.

The vulnerable path is known to affect Zimbra 10.1.16, was not present in the
original 10.1.0 release, and is fixed in 10.1.17. Its exact introduced release
is unknown. Technical details appear in
[Rapid7's Part One research](https://www.rapid7.com/blog/post/ve-breaking-zimbra-identity-boundaries-part-1/),
the [tracker writeup](https://github.com/jburgess-r7/zimbra-vulnerability-tracker/blob/main/vulnerabilities/CVE-2026-73571.md), and
the [vendor advisories](https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories).

`check` authenticates, confirms that both accounts use the same mailbox server, and reads the Zimbra version.
It does not deliver a message. Exact 10.1.16 builds return
`Appears`; 10.1.17 and later return `Safe`; versions between the confirmed
10.1.0 and 10.1.16 boundaries return `Detected` because the introduced release
has not been established.

### Lab setup

Testing used Zimbra 10.1.16 Network Edition on an Ubuntu Server 22.04 x64 VM.
Use a saved 10.1.16 VM or obtain the archived packages for that release.
Zimbra's current package repository installs a newer, fixed release. A public Docker image has not been tested.

To build the VM from archived packages:

1. Configure a static address, a hostname such as `mail.lab.local`, and a mail domain such as `lab.local`.
   Both the VM and the Metasploit workstation must resolve the hostname.
   Use private DNS with an A record for the hostname and an MX record for the mail domain.
   Follow Zimbra's [single-server installation guide][zimbra-install] for the remaining OS and sizing requirements.
2. Download the [Ubuntu 22.04 base installer][zimbra-base] and obtain a [10.1 trial activation ID][zimbra-trial].
   Configure apt to use a repository containing the archived 10.1.16 package set.
   The base installer alone does not reproduce 10.1.16.
3. Extract the installer and run `sudo ./install.sh --licensekey '<trial-activation-id>'`.
   Answer `N` when asked to use Zimbra's package repository.
   Install LDAP, MTA, mailbox/store, proxy, memcached, and the license service on the same VM.
   Set the mail domain to `lab.local` and configure the installer-created administrator.
4. Install the exact package versions from the archive's manifest.
   For a tab-separated `installed-packages.tsv` containing package name and version in its first two columns,
   run the following from the directory containing that file:

```bash
mapfile -t packages < <(awk -F '\t' '{ print $1 "=" $2 }' installed-packages.tsv)
sudo apt-get install --allow-downgrades "${packages[@]}"
sudo -iu zimbra /opt/zimbra/bin/zmcontrol restart
sudo -iu zimbra /opt/zimbra/bin/zmcontrol -v
sudo -iu zimbra /opt/zimbra/bin/zmlicense -c
```

Confirm that the installed release is `10.1.16` and the license is active.
Keep the public Zimbra package repository disabled while testing this snapshot.

For a local-only hostname resolved through `/etc/hosts`, configure [native LMTP host lookup][zimbra-lmtp]
so the MTA can deliver into the mailbox:

```bash
sudo -iu zimbra /opt/zimbra/bin/zmprov ms mail.lab.local zimbraMtaLmtpHostLookup native
sudo -iu zimbra /opt/zimbra/bin/zmmtactl restart
```

Create two ordinary accounts on the VM. Do not grant either account administrator, `sendAs`, or `sendOnBehalfOf` rights.
The attacker's own Inbox can be the recipient, so only the attacker password is needed by the module.

```bash
sudo -iu zimbra /opt/zimbra/bin/zmprov ca attacker@lab.local '<attacker-password>'
sudo -iu zimbra /opt/zimbra/bin/zmprov ca victim@lab.local '<victim-password>'
sudo -iu zimbra /opt/zimbra/bin/zmprov ga attacker@lab.local zimbraMailHost
sudo -iu zimbra /opt/zimbra/bin/zmprov ga victim@lab.local zimbraMailHost
sudo -iu zimbra /opt/zimbra/bin/zmprov ckr account victim@lab.local attacker@lab.local sendAs
sudo -iu zimbra /opt/zimbra/bin/zmprov ckr account victim@lab.local attacker@lab.local sendOnBehalfOf
```

Both `zimbraMailHost` values must match, and both rights checks must deny access.
Set `USERNAME` and `RECIPIENT` to `attacker@lab.local`, and `VICTIM` to `victim@lab.local`.
To test separate recipient credentials, create a third ordinary account and use it for `RECIPIENT` and `VERIFY_USERNAME`.

[zimbra-install]: https://zimbra.github.io/documentation/zimbra-10/single-server-install.html
[zimbra-base]: https://files.zimbra.com/downloads/10.1.0_GA/zcs-NETWORK-10.1.0_GA_4655.UBUNTU22_64.20240819064312.tgz
[zimbra-trial]: https://www.zimbra.com/product/download/
[zimbra-lmtp]: https://wiki.zimbra.com/wiki/Incoming_Mail_Problems

## Verification Steps

1. Start Metasploit Framework from the source checkout.
2. Run: `use auxiliary/admin/http/zimbra_email_impersonation`
3. Run: `set RHOST <zimbra-host>`
4. Run: `set VHOST <zimbra-hostname>` when it differs from `RHOST`.
5. Set `USERNAME` and `PASSWORD` to an ordinary account.
6. Set `VICTIM` to a different mailbox on the same mailbox server with no delegation grant to the attacker.
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

For the two-account setup above, locate the test copies with the full subject printed by the module.
Delete only their returned message IDs:

```bash
sudo -iu zimbra /opt/zimbra/bin/zmmailbox -z -m attacker@lab.local s -t message 'in:inbox subject:"<exact-test-subject>"'
sudo -iu zimbra /opt/zimbra/bin/zmmailbox -z -m victim@lab.local s -t message 'in:sent subject:"<exact-test-subject>"'
sudo -iu zimbra /opt/zimbra/bin/zmmailbox -z -m attacker@lab.local dm <inbox-message-id>
sudo -iu zimbra /opt/zimbra/bin/zmmailbox -z -m victim@lab.local dm <sent-message-id>
```

Repeat the two searches to confirm those test copies are gone.

## Options

### USERNAME

Ordinary attacker account used for Zimbra SOAP authentication. It does not need
a delegation grant or licensed feature.

### PASSWORD

Password for `USERNAME`.

### VICTIM

Account selected as the message From and impersonated sender.
The module resolves this account before delivery and requires it to be a different account on the attacker's mailbox server.

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

### Zimbra 10.1.16 Network Edition on Ubuntu 22.04 x64

This run used the archived-package setup above and the attacker's own Inbox for verification.
The selected sender's password was not supplied to the module.

```text
msf auxiliary(admin/http/zimbra_email_impersonation) > check
[+] 192.168.80.136:443 - The target appears to be vulnerable. Authenticated attacker@lab.local and local target victim@lab.local are confirmed on known affected 10.1.16
msf auxiliary(admin/http/zimbra_email_impersonation) > run
[*] Running module against 192.168.80.136
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Authenticated attacker@lab.local and local target victim@lab.local are confirmed on known affected 10.1.16
[*] Sending a delegated message from victim@lab.local to attacker@lab.local
[*] Subject: MSF-IMPERSONATION-20261111T121557Z-efb73e0d [MSF-24f7136ea63988fee6dd0382]
[+] Verified Inbox delivery from victim@lab.local to attacker@lab.local
[*] Auxiliary module execution completed
```

Both test messages were deleted by ID after this capture, and the matching Inbox and Sent searches returned no results.

Earlier 10.1.16 tests also covered separate recipient verification
credentials. The recipient Inbox showed the selected sender, while the exact
matching message appeared in that sender's Sent folder. Both plain and HTML
message formats passed. The database-backed run recorded one `zimbra-soap`
service, one successful ordinary-account login, and the verified vulnerability.
