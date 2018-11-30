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
- `use auxiliary/scanner/msmail/identify`
- `set RHOSTS <target>`
- `run`
- **Verify** the result is as expected
