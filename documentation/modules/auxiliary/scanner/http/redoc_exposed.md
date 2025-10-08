## ReDoc API Docs UI Exposed

Detects publicly exposed ReDoc API documentation pages by looking for known DOM elements, script names, and titles. The module is read-only and makes safe GET requests.

### Module Options

* **RHOSTS** (required): Target address range or CIDR identifier.
* **RPORT**: Default `80` (overridable via `DefaultOptions` or at runtime).
* **SSL**: HTTPS support is registered by default (set if needed).
* **REDOC_PATHS**: Comma-separated custom paths to probe. If unset, defaults to:
  `/redoc,/redoc/,/docs,/api/docs,/openapi`.

### Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/http/redoc_exposed`
3. `set RHOSTS <target-or-range>`
4. (Optional) `set REDOC_PATHS /redoc,/docs`
5. (Optional) `set SSL true`
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
* **SideEffects**: Requests may appear in server logs (`IOC_IN_LOGS` if applicable).
