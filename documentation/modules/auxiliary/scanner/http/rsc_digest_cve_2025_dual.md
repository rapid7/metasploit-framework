# Next.js / React RSC Digest Exposure Scanner (CVE-2025-55182 / CVE-2025-66478)

## Module Overview

This Metasploit auxiliary scanner module detects React Server Components (RSC) digest exposure vulnerabilities affecting both React and Next.js applications. The module performs safe, non-invasive detection by sending a crafted RSC payload and analyzing the server's response for digest reflection behavior.

**Targeted Vulnerabilities:**
- **CVE-2025-55182** (React2Shell): RSC digest exposure in React applications
- **CVE-2025-66478**: RSC digest exposure in Next.js applications

The scanner identifies vulnerable endpoints where attackers can inject malicious RSC payloads that trigger `NEXT_REDIRECT` errors with attacker-controlled digest values. In specific configurations, this behavior can be chained to achieve remote command execution, depending on the server-side RSC execution context and Node.js runtime privileges.

## Affected Vulnerabilities

### CVE-2025-55182 (React2Shell)
React Server Components implementation flaw allowing prototype pollution through crafted multipart form-data payloads. When exploited, attackers can inject arbitrary JavaScript code via the `_prefix` field in RSC payload structures, leading to code execution in the Node.js runtime. Actual remote command execution depends on the server-side RSC execution context and Node.js privileges.

**Affected versions:**
- React Server Components implementations prior to patched versions (exact affected version range depends on the specific React Server Components implementation and deployment configuration)
- Applications using `react-server-dom-webpack` with vulnerable RSC parsing logic

### CVE-2025-66478 (Next.js RSC)
Next.js-specific implementation vulnerability in React Server Components handling. Similar to CVE-2025-55182, this allows injection of malicious payloads through RSC digest manipulation, causing the server to execute arbitrary commands and reflect results in error digests. Actual remote command execution depends on the server-side RSC execution context and Node.js privileges.

**Affected versions:**
- Next.js applications running vulnerable React Server Components implementations, including versions up to 16.0.6 (as observed in public PoCs)
- Applications using Next.js App Router with Server Actions enabled

**References:**
- https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478
- https://github.com/msanft/CVE-2025-55182
- https://github.com/subzer0x0/React2Shell

## Parameter Description

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `RHOSTS` | String | - | Yes | Target host(s) to scan (single IP, range, or file) |
| `RPORT` | Integer | 3000 | Yes | Target port number (common: 3000, 3001) |
| `TARGETURI` | String | `/` | Yes | Base path to test (e.g., `/`, `/api/action`) |
| `TIMEOUT` | Integer | 10 | Yes | HTTP request timeout in seconds |

**Usage Notes:**
- The scanner works against any HTTP endpoint accepting RSC payloads
- Default port `3000` is common for React apps; `3001` often used for Next.js
- `TARGETURI` should point to the application's RSC action endpoint
- Increase `TIMEOUT` for slow or remote targets

## Usage Examples

### Example 1: Scan single target (React2Shell - port 3000)
```
msf > use auxiliary/scanner/http/rsc_digest_cve_2025_dual
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set RHOSTS 10.211.55.65
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set RPORT 3000
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > run

[*] Scanning 10.211.55.65:3000
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example 2: Scan Next.js application (port 3001)
```
msf > use auxiliary/scanner/http/rsc_digest_cve_2025_dual
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set RHOSTS 10.211.55.65
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set RPORT 3001
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > run

[*] Scanning 10.211.55.65:3001
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3001
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example 3: Scan multiple targets
```
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set RHOSTS 192.168.1.0/24
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set THREADS 10
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > run
```

## Return Results Interpretation

### Vulnerable Detection
```
[+] VULNERABLE: RSC digest exposure detected on <IP>:<PORT>
```
**Meaning:** The target exhibits **confirmed vulnerable behavior consistent with known RSC digest exposure**. The server responded with an RSC error message containing the digest value in the expected format (`1:E{"digest":...}`). This indicates the application processes RSC payloads and reflects error digests, making it exploitable for RCE under certain conditions.

**Technical Details:**
- HTTP response body matches regex: `/^1:E\{.*"digest":.*\}/m`
- Response Content-Type: `text/x-component`
- HTTP status: typically 500

### Potentially Vulnerable
```
[+] POTENTIALLY VULNERABLE: Unstable digest behavior on <IP>:<PORT>
```
**Meaning:** The server exhibits RSC-related behavior but digest reflection is **inconsistent**. The response contains:
- HTTP 500 status
- Content-Type: `text/x-component`
- Contains the word "digest" but not in the expected format

**Action Required:** Manual verification recommended with additional payloads.

### RSC Channel Detected
```
[*] RSC channel detected but no digest reflection on <IP>:<PORT>
```
**Meaning:** The server accepts RSC payloads (responds with `text/x-component`) but does **not** reflect digest values. This may indicate:
- Patched version
- Custom RSC implementation
- Different error handling configuration

### Not Vulnerable
```
[*] No RSC digest behavior detected on <IP>:<PORT>
```
**Meaning:** The target does **not** appear vulnerable. The response does not match any RSC digest patterns.

## Verification & Legitimacy Statement

### Module Validation

This module has been thoroughly tested and validated against live vulnerable instances using multiple independent tools. Independent validation performed using Nuclei and Nmap NSE scripts.

**Verification Tools Repository:** https://github.com/inwpu/RSC-VulnLab

This repository contains all validation scripts, vulnerable lab environments, and detection tools used to verify this module:
- Nuclei templates (`nuclei-custom/`)
- Nmap NSE scripts (`nmap-nse/`)
- Docker-based vulnerable lab setup (`next_rsc_two_cves_lab/`)
- Interactive RCE shell proof-of-concepts

#### 1. Metasploit Module Validation (This Module)
Successfully detected vulnerabilities on test environments:
```
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3000
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3001
```

#### 2. Nuclei Template Validation
Cross-verified using official Nuclei templates with **confirmed RCE execution**:

**CVE-2025-55182 (React2Shell - Port 3000):**
```bash
nuclei -u http://127.0.0.1:3000 \
  -t react2shell-cve-2025-55182-rce-body-id.yaml \
  -severity high

[react2shell-cve-2025-55182-rce-body-id] [http] [high] http://127.0.0.1:3000/
  ["digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
```

**CVE-2025-66478 (Next.js - Port 3001):**
```bash
nuclei -u http://127.0.0.1:3001 \
  -t nextjs-cve-2025-66478-rce-3001.yaml \
  -severity high

[nextjs-cve-2025-66478-rce-3001] [http] [high] http://127.0.0.1:3001
  ["uid=0(root) gid=0(root) groups=0(root)"]
```

#### 3. Nmap NSE Script Validation
Verified using custom NSE detection scripts:
```bash
nmap -p 3000,3001 \
  --script react2shell-cve-2025-55182-detect.nse,nextjs-rsc-cve-2025-66478-detect.nse \
  127.0.0.1

PORT     STATE SERVICE
3000/tcp open  ppp
| react2shell-cve-2025-55182-detect: VULNERABLE
|   Observed digest: 1917316682

3001/tcp open  nessus
| nextjs-rsc-cve-2025-66478-detect: VULNERABLE
|   Observed digest: 3420135227
```

#### 4. Interactive RCE Shell Validation
**CVE-2025-55182 Interactive Shell (Port 3000):**
```bash
$ python poc_shell.py
Target: http://10.211.55.65:3000

rsc-shell> id
[+] HTTP 500
>>> Command output:
uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)

rsc-shell> whoami
[+] HTTP 500
>>> Command output:
nextjs
```

**CVE-2025-66478 Interactive Shell (Port 3001):**
```bash
$ python3 nextjs_66478_shell.py
Target: http://10.211.55.65:3001

nextjs-rsc> id
[+] HTTP 500
>>> Command output:
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon)...

nextjs-rsc> whoami
[+] HTTP 500
>>> Command output:
root
```

### Legal & Ethical Use Statement

**IMPORTANT:** This module is designed exclusively for **authorized security testing** and **defensive security purposes**.

**Permitted Use Cases:**
- Authorized penetration testing with explicit written consent
- Security audits of your own infrastructure
- Academic research in controlled lab environments
- Vulnerability assessment by security professionals

**Prohibited Activities:**
- Scanning or exploiting systems without explicit authorization
- Malicious attacks against third-party infrastructure
- Unauthorized access to computer systems
- Any activity violating local or international laws

**User Responsibility:**
By using this module, you acknowledge that:
1. You have obtained proper authorization before scanning any target
2. You understand applicable laws and regulations in your jurisdiction
3. The module author and Metasploit project are not responsible for misuse
4. Unauthorized use may result in criminal prosecution
5. The author assumes no liability for any damages resulting from the use or misuse of this module

**Disclosure Policy:**
This module was developed following responsible disclosure practices. All referenced vulnerabilities have been publicly disclosed with CVE assignments. Users should only test against patched systems in authorized environments.

---

**Author:** hxorz (aisnnu@gmail.com)
**License:** Metasploit Framework License (BSD-3-Clause)
**Disclosure Date:** 2025-12-08
