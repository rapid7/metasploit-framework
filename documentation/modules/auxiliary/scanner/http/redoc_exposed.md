## Summary
This module detects publicly exposed **ReDoc** API documentation pages.  
It performs safe, read-only HTTP GET requests and reports likely ReDoc instances based on common HTML markers.

## Module name
`auxiliary/scanner/http/redoc_exposed`

## Options
* **RPORT** – Target TCP port (default: 80)  
* **SSL** – Enable TLS (default: false)  
* **REDOC_PATHS** – Optional comma-separated list of paths to probe. When unset, the module probes: `/redoc, /redoc/, /docs, /api/docs, /openapi`.

## Verification steps
1. Start `msfconsole`  
2. `use auxiliary/scanner/http/redoc_exposed`  
3. `set RHOSTS <target or file:/path/to/targets.txt>`  
4. (Optional) `set REDOC_PATHS /redoc,/docs`  
5. (Optional) `set RPORT <port>` and/or `set SSL true`  
6. `run`

### Expected

`[+] <ip> - ReDoc likely exposed at <path>`

### Scanning notes
- DOM-driven checks via `get_html_document`:
  - `<redoc>` / `redoc-` custom elements
  - `#redoc` container
  - `<script src="...redoc(.standalone).js">`
- Falls back to body/title heuristics if DOM parsing is unavailable.
- No intrusive actions; **read-only** HTTP GET requests only.

### Example session

use auxiliary/scanner/http/redoc_exposed
set RHOSTS 127.0.0.1
set RPORT 8001
set SSL false
run
