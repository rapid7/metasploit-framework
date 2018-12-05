OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

**Identify Command**
- Used for gathering information about a host that may be pointed towards an Exchange or o365 tied domain
- Queries for specific DNS records related to Office 365 integration
- Attempts to extract internal domain name for onprem instance of Exchange
- Identifies services vulnerable to time-based user enumeration for onprem Exchange
- Lists password-sprayable services exposed for onprem Exchange host

**Note:**  Currently uses RHOSTS which resolves to an IP which is NOT desired, this is currently being fixed 

## Verification

- Start `msfconsole`
- `use auxiliary/scanner/msmail/host_id`
- `set RHOSTS <target>`
- `run`

*Results should look like below:*

```
msf5 > use auxiliary/scanner/msmail/host_id
msf5 auxiliary(scanner/msmail/host_id) > set RHOSTS <host>
RHOSTS => <host>
msf5 auxiliary(scanner/msmail/host_id) > run

[*] Running for <ip>...
[*] Attempting to harvest internal domain:
[*] Internal Domain:
[*] <domain>
[*] [-] Domain is not using o365 resources.
[*] Identifying endpoints vulnerable to time-based enumeration:
[*] [+] https://<host>/Microsoft-Server-ActiveSync
[*] [+] https://<host>/autodiscover/autodiscover.xml
[*] [+] https://<host>/owa
[*] Identifying exposed Exchange endpoints for potential spraying:
[*] [+] https://<host>/oab
[*] [+] https://<host>/ews

```