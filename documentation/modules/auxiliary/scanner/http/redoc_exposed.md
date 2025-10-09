## ReDoc API Docs UI Exposed

Detects publicly exposed ReDoc API documentation pages by looking for known DOM elements and script names. The module is read-only and sends safe `GET` requests.

### Module Options

- **RHOSTS** (required): Target address range or CIDR identifier.
- **RPORT**: Default `80` (from `DefaultOptions`).
- **SSL**: Enable to negotiate HTTPS to the target.
- **REDOC_PATHS** (required): Comma-separated paths to probe. **Default**:  
  `/redoc,/redoc/,/docs,/api/docs,/openapi`

### How It Works

- Prefers DOM checks (`<redoc>`, `#redoc`, or scripts containing `redoc` / `redoc.standalone`).
- Falls back to title/body heuristics for “redoc”.
- Considers only **2xx** and **403** responses (avoids noisy redirects).

### Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/http/redoc_exposed`
3. `set RHOSTS <target-or-range>`
4. (Optional) `set SSL true`
5. (Optional) `set REDOC_PATHS /redoc,/docs`
6. `run`

### Scenarios

```text
msf6 > use auxiliary/scanner/http/redoc_exposed
msf6 auxiliary(scanner/http/redoc_exposed) > set RHOSTS 192.0.2.0/24
msf6 auxiliary(scanner/http/redoc_exposed) > run
[+] 192.0.2.15 - ReDoc likely exposed at /docs
[*] 192.0.2.23 - no ReDoc found
```
### Notes

* **Stability**: `CRASH_SAFE` (GET requests only).
* **Reliability**: No session creation.
* **SideEffects**: Requests may appear in server logs (`IOC_IN_LOGS`).

