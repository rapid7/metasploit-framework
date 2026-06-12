## Vulnerable Application

This module detects Metasploit `exploit/multi/handler` listeners (and any other
**staged** `reverse_tcp` payload handler) on a network by abusing the staging
protocol.

When a victim connects to a staged `reverse_tcp` handler, the handler
immediately transmits the second stage **without waiting for any client input**
- it "talks first". Almost no legitimate TCP service sends a large binary or
base64/zlib blob immediately on connect, which makes this behavior a reliable
fingerprint.

The module recognizes several "handler talks first" behaviors:

* **Windows native** stagers send a little-endian (`pack('V')`) length followed
  by a binary stage (for meterpreter this is the `metsrv` reflective DLL,
  ~200 KB+ for x64; for shells a small <1 KB stage).
* **Python** stagers send a big-endian (`pack('N')`) length followed by a
  base64+zlib text stage.
* **PHP / Java** stagers send a big-endian (`pack('N')`) length followed by a
  PHP-source / JAR stage.
* **Linux / OSX native** meterpreter stagers send the raw machine-code stage
  with no length prefix at all.
* **Unix staged shells** send a tiny raw `execve("/bin/sh")` shellcode stage
  (detected via the embedded `/bin/sh` string).
* **Reverse command shells** (`shell_reverse_tcp`, etc.): the
  `Msf::Sessions::CommandShell` handler verifies the shell by sending
  `echo <random-token>` on connect, which is a reliable Metasploit signature.
* **Java / Android (Dalvik)** stagers send a big-endian length prefix followed
  by a jar/dex stage (detected via the `PK`/`META-INF` markers).

When a port does not volunteer a stage (the handler waits for the client), the
module additionally sends an HTTP request to fingerprint Metasploit's
**HTTP-based handlers** (both plaintext and, optionally, over TLS):

* **`reverse_http` / `reverse_https` Meterpreter handlers** answer `200 OK` with
  the default `It works!` body to *any* unknown URI (a real server would return
  `404`), with `Server: Apache`.
* **Rex HTTP servers** (`web_delivery`, the `fetch` payload servers, and most
  exploit-module HTTP servers) return a distinctive Rex `404` page
  (`<h1>Not found</h1>The requested URL ... was not found on this server.`).

### Capturing operator AutoRunScript / follow-up commands

When `ECHO_BACK` is enabled (default) and a reverse command-shell handler is
found, the module echoes the verification token back. This marks the shell
"valid" on the operator's console, after which the handler runs any configured
`InitialAutoRunScript` / `AutoRunScript` against what it believes is a live
session - and those commands are written down the socket to us. The module
captures and reports them, which can leak the operator's post-exploitation
automation. With no AutoRunScript configured, the handler simply stops after
verification (nothing further is sent).

### Detectability summary by transport

These figures come from spinning up one representative listener for every
distinct `(os/language x staged? x type x transport)` combination (203 of them,
collapsing arch variants that share a wire fingerprint) and scanning them. The
counts are the number of the 1090 total reverse payloads that map to each
transport class, and how many fall into a detectable class.

| Transport class | Example payloads | Total | Detected | How |
|---|---|---:|---:|---|
| tcp | reverse_tcp (+dns/uuid-less variants) | 544 | 318 | talk-first stage / echo / binary burst |
| http | reverse_http / reverse_winhttp | 124 | 96 | HTTP probe -> It works! |
| https | reverse_https / reverse_winhttps | 108 | 86 | HTTPS probe -> It works! |
| tcp_rc4 | reverse_tcp_rc4 | 102 | 44 | RC4-encrypted stage (partial) |
| tcp_uuid | reverse_tcp_uuid | 81 | 47 | stage after 16-byte UUID |
| cmdshell | interpreter reverse shells | 42 | 23 | echo <token> probe (timing) |
| tcp_ssl | reverse_tcp_ssl | 31 | 19 | SSL probe reads stage/echo |
| named_pipe | reverse_named_pipe (SMB) | 30 | 0 | SMB named pipe - not probed |
| udp | reverse_udp | 15 | 6 | UDP datagram -> stage |
| sctp | reverse_sctp | 13 | 0 | SCTP - not probed |


Notes on the partials/zeros:

* **tcp_rc4 / tcp_uuid**: the RC4-encrypted stage looks like a high-entropy
  binary burst (still flagged, lower confidence); UUID payloads prepend 16
  bytes before the length field. Both are caught when they fall back to the
  generic "unsolicited binary burst" rule.
* **tcp_ssl**: caught by the SSL probe, which sends an HTTP request and then
  classifies the reply, so it reads `reverse_https` (`It works!`),
  `shell_reverse_tcp_ssl` (`echo <token>` over TLS) and the staged
  `reverse_tcp_ssl` burst with a single round-trip.
* **named_pipe (SMB)** and **sctp**: not TCP or UDP, so this scanner does not
  probe them - listed for completeness only.
* **silent stageless**: stageless payloads that wait for the client and are not
  HTTP handlers (some meterpreter and shells) cannot be elicited and look like a
  plain open port.

The full per-type matrix (sorted by os/language, staged, type, transport) is in
the [Full payload matrix](#full-payload-matrix) appendix at the end of this
document.

### Empirical validation (723 live listeners)

The detector was validated end-to-end by starting a real `multi/handler`
listener for **every one of the 723 reverse payloads** that bind under
`multi/handler` (LPORT 10000+, scanned from a *separate*, lightly-loaded
console) and confirming what each is classified as:

| Result | Count | |
|---|---:|---|
| Detected (passive probes off) | **673 / 723** | 93.1% |
| + `DEEP_PROBE` (double handlers + pingback) | **~698 / 723** | 96.5% |
| Not detected - *expected* (passive handlers) | 24 | see below |

Confidence of the base 673: ~460 high, ~78 medium, ~135 low. Transports covered
include tcp, http(s), tcp_ssl, tcp_rc4, tcp_uuid, fetch (http/https/tftp) and
udp.

`DEEP_PROBE` (on by default) actively provokes two families that are silent on a
single connection:

* **`cmd/unix/reverse`, `reverse_openssl`, `reverse_ssl_double_telnet` (+ their
  `php/unix/cmd` mirrors) (6)** use `Msf::Handler::ReverseTcpDouble` - they wait
  for *two* connections, then write `echo <token>;` to both to pair them. The
  scanner opens a second connection (plaintext and TLS) and reads that probe -
  **high confidence**.
* **`pingback_*` (19)** read a 16-byte UUID then close, sending nothing. The
  scanner writes 16 bytes and confirms the handler closes near-instantly with no
  reply - **low confidence** (behavioral; any service that drops the connection
  on 16 bytes of junk looks similar).

The remaining 24 are genuinely passive and not elicitable with a simple probe:

* **`powershell_reverse_tcp` / `_ssl` (20)** - the handler waits for the live
  PowerShell to speak first; it stays silent for >22s to a UUID, a fake banner
  and a null byte alike, so there is nothing to fingerprint.
* **mainframe z/OS shell (2)**, **`osx/aarch64/shell_reverse_tcp` (1)**, and a
  stageless `cmd/unix/php/meterpreter_reverse_tcp` (1) - silent on a bare
  connect.

> Detection of reverse *shells* (`echo <token>`) is timing-sensitive: the probe
> only fires once the handler treats the connection as a live shell. Under heavy
> load (many handlers in one console plus the scanner) that bootstrap is delayed
> and shells are missed. Run the scanner from a **separate console** and/or
> raise `FIRST_BYTE_WAIT` and they detect reliably - this accounted for the bulk
> of the gap between a first pass and the 673 total above.

### Limitations

* **Some passive handlers cannot be detected.** When the handler volunteers
  nothing, is *not* an HTTP handler, and cannot be provoked by `DEEP_PROBE`, the
  port just looks open. With `DEEP_PROBE` on, the `ReverseTcpDouble`/double-SSL
  shells (`cmd/unix/reverse`, `reverse_openssl`, `reverse_ssl_double_telnet`) and
  `pingback_*` are recovered; what is left is `powershell_reverse_tcp(_ssl)`
  (waits for the live PowerShell to talk first) and a few stageless/exotic shells
  - ~24 of 723.
* **Reverse-shell `echo` detection is timing-dependent.** The handler only
  emits its `echo` probe once it treats the connection as a live shell, which is
  delayed when the operator's console is heavily loaded. Scan from a *separate*
  console and/or increase `FIRST_BYTE_WAIT` if shells are being missed.
* **Encrypted stages are low-confidence.** RC4 (`reverse_tcp_rc4`) and other
  encrypted/stageless streams have no parseable framing, so they are only
  flagged generically as an "unsolicited binary burst."
* The technique fingerprints the **transport/staging behavior**, not the exact
  module. Several payloads share a family fingerprint (e.g. linux vs osx native
  stages, or the legacy `reverse_nonx`/`reverse_ord` stager shellcode, are
  indistinguishable on the wire), so the reported payload is a best-effort
  family guess.

### WARNING

Connecting to a live handler causes it to send a stage and attempt to create a
session. On the operator's `msfconsole` this prints a `Sending stage (...)`
message and leaves a failed/dead session. This is an intentional, observable
side effect (`IOC_IN_LOGS`).

### Setting up handlers for testing

Start an `exploit/multi/handler` (or use `to_handler` / web_delivery) with a
staged payload, for example:

```
use exploit/multi/handler
set payload python/meterpreter/reverse_tcp
set lhost 127.0.0.1
set lport 4445
run -j

set payload linux/x64/meterpreter/reverse_tcp
set lport 4446
run -j

set payload windows/x64/meterpreter/reverse_tcp
set lport 4448
run -j
```

## Verification Steps

1. Start one or more staged `reverse_tcp` handlers as shown above.
2. Start `msfconsole`
3. `use auxiliary/scanner/msf/handler_detect`
4. `set RHOSTS 127.0.0.1`
5. `set PORTS 4444-4464`
6. `run`
7. You should see `[+]` lines identifying each detected handler and the
   fingerprinted payload family.

## Options

### PORTS

The list of TCP ports to probe on each host, in the usual Metasploit portspec
format (e.g. `4444-4460,5555`). Defaults to `4444-4464`.

### TIMEOUT

The socket connect timeout in seconds. Default `1`.

### FIRST_BYTE_WAIT

How long (seconds) to wait for the handler to send the first stage/probe
bytes after connecting. Default `5`. Reverse-shell handlers emit their
`echo` verification probe a little late, so allow some slack; increase further
on slow/high-latency links.

### IDLE_TIMEOUT

How long (seconds) to wait for additional stage data before assuming the
stage is fully received. Default `0.75`.

### MAX_STAGE_SIZE

Maximum number of stage bytes to read while fingerprinting. Reading the full
stage allows the length-prefix to be matched exactly (high confidence). Default
`2097152` (2 MB).

### HTTP_PROBE

When a port does not volunteer a stage, send an HTTP request to fingerprint
Metasploit's HTTP-based handlers (`reverse_http`, `web_delivery`, `fetch`).
Default `true`.

### HTTP_SSL_PROBE

In addition to the plaintext HTTP probe, attempt an SSL/TLS request to catch
`reverse_https` / HTTPS `fetch` servers, and to read the stage/echo of
`reverse_tcp_ssl` handlers through the TLS handshake. Default `true`.

### SCAN_UDP

Also probe each port over UDP. A `reverse_udp` handler waits for any inbound
datagram and then sends the stage back, so a single probe datagram elicits the
same staging fingerprint. Default `false`.

### ECHO_BACK

When a command-shell `echo <token>` verification probe is seen, echo the token
back to mark the shell valid and capture any follow-up commands the handler
sends (for example an operator's `AutoRunScript`). Default `true`.

### ECHO_FOLLOWUP_WAIT

How long (seconds) to keep reading after echoing the token back, to capture
`AutoRunScript` / operator commands. Default `8`.

### CONCURRENCY

The number of concurrent ports to check per host. Default `10`.

### DEEP_PROBE

For ports that stay silent on the first connection, actively try to provoke
passive handlers before giving up (default `true`):

* open a **second connection** (plaintext and, if `HTTP_SSL_PROBE`, TLS) to make
  a `ReverseTcpDouble` handler pair them and emit its `echo` probe
  (`cmd/unix/reverse`, `reverse_openssl`, `reverse_ssl_double_telnet`);
* write a **16-byte UUID** and watch for the immediate, reply-less close that
  identifies a `pingback_*` handler.

This opens a few extra connections per silent port. Set to `false` for the
quietest possible scan.

## Scenarios

### Example run against a host running several staged handlers

```
msf6 auxiliary(scanner/msf/handler_detect) > run
```

## Full payload matrix

One row per distinct payload type (arch variants collapsed; the *Variants* column
is how many of the 1090 reverse payloads map to that row). Detection results are
empirical from live representative listeners. `n/t (no listener)` means that
representative did not start a TCP/UDP listener under `multi/handler` (needs
extra options, is SMB/SCTP, or is an exotic/unsupported OS).

| OS / Language | Staged | Type | Transport | Variants | Detected | Method / Notes |
|---|---|---|---|---:|---|---|
| aix | single | shell | tcp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| android | staged | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| android | staged | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| android | staged | meterpreter | tcp | 1 | YES (tcp) | BE length prefix (jar/dex) |
| android | staged | shell | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| android | staged | shell | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| android | staged | shell | tcp | 1 | YES (tcp) | BE length prefix (jar/dex) |
| android | single | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| android | single | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| android | single | meterpreter | tcp | 1 | YES (tcp) | binary burst, no prefix |
| apple_ios | single | meterpreter | http | 2 | YES (tcp) | HTTP probe ("It works!") |
| apple_ios | single | meterpreter | https | 2 | YES (tcp) | HTTPS probe ("It works!") |
| apple_ios | single | meterpreter | tcp | 2 | YES (tcp) | binary burst, no prefix |
| apple_ios | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| bsd | staged | shell | tcp | 2 | YES (tcp) | raw /bin/sh shellcode |
| bsd | single | other | tcp | 1 | YES (tcp) | binary burst, no prefix |
| bsd | single | shell | tcp | 7 | YES (tcp) | echo <token> probe |
| bsdi | staged | shell | tcp | 1 | YES (tcp) | raw /bin/sh shellcode |
| bsdi | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| cmd/linux | staged | meterpreter | sctp | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/linux | staged | meterpreter | tcp | 24 | YES (tcp) | LE length prefix (shell stage) |
| cmd/linux | staged | meterpreter | tcp_uuid | 3 | YES (tcp) | binary burst, no prefix |
| cmd/linux | staged | shell | sctp | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/linux | staged | shell | tcp | 24 | YES (tcp) | LE length prefix (shell stage) |
| cmd/linux | staged | shell | tcp_uuid | 3 | YES (tcp) | raw /bin/sh shellcode |
| cmd/linux | single | meterpreter | http | 24 | YES (tcp) | HTTP probe ("It works!") |
| cmd/linux | single | meterpreter | https | 24 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/linux | single | meterpreter | tcp | 24 | YES (tcp) | binary burst, no prefix |
| cmd/linux | single | other | tcp | 6 | no (silent) | handler waits for client (stageless) |
| cmd/linux | single | shell | tcp | 36 | YES (tcp) | echo <token> probe |
| cmd/mainframe | single | shell | tcp | 1 | no (silent) | handler waits for client (stageless) |
| cmd/unix | staged | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| cmd/unix | staged | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/unix | staged | meterpreter | tcp | 2 | YES (tcp) | BE length prefix (php) |
| cmd/unix | staged | meterpreter | tcp_ssl | 1 | YES (tcp) | BE length prefix (base64/zlib) |
| cmd/unix | staged | meterpreter | tcp_uuid | 2 | YES (tcp) | BE length prefix (php) |
| cmd/unix | single | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| cmd/unix | single | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/unix | single | meterpreter | tcp | 2 | no (silent) | handler waits for client (stageless) |
| cmd/unix | single | other | cmdshell | 19 | no (silent) | handler waits for client (stageless) |
| cmd/unix | single | other | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/unix | single | other | tcp | 6 | no (silent) | handler waits for client (stageless) |
| cmd/unix | single | other | tcp_ssl | 6 | YES (tcp) | echo <token> probe |
| cmd/unix | single | shell | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/unix | single | shell | tcp | 1 | no (silent) | handler waits for client (stageless) |
| cmd/unix | single | shell | tcp_ssl | 1 | YES (tcp) | echo <token> probe |
| cmd/unix | single | shell | udp | 1 | no (silent) | handler waits for client (stageless) |
| cmd/windows | staged | custom | http | 16 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | https | 16 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | named_pipe | 8 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | tcp | 26 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | tcp_rc4 | 11 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | tcp_uuid | 8 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | custom | udp | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | dllinject | http | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | dllinject | tcp | 21 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | dllinject | tcp_rc4 | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | dllinject | tcp_uuid | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | meterpreter | http | 17 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | staged | meterpreter | https | 17 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | staged | meterpreter | named_pipe | 8 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | meterpreter | tcp | 27 | YES (tcp) | LE length prefix (metsrv) |
| cmd/windows | staged | meterpreter | tcp_rc4 | 11 | YES (tcp) | binary burst, no prefix |
| cmd/windows | staged | meterpreter | tcp_ssl | 1 | YES (tcp) | BE length prefix (base64/zlib) |
| cmd/windows | staged | meterpreter | tcp_uuid | 9 | YES (tcp) | LE length prefix (metsrv) |
| cmd/windows | staged | patchupdllinject | tcp | 18 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | patchupdllinject | tcp_rc4 | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | patchupdllinject | tcp_uuid | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | patchupmeterpreter | tcp | 18 | YES (tcp) | LE length prefix (shell stage) |
| cmd/windows | staged | patchupmeterpreter | tcp_rc4 | 6 | YES (tcp) | binary burst, no prefix |
| cmd/windows | staged | patchupmeterpreter | tcp_uuid | 3 | YES (tcp) | LE length prefix (shell stage) |
| cmd/windows | staged | shell | tcp | 23 | YES (tcp) | LE length prefix (shell stage) |
| cmd/windows | staged | shell | tcp_rc4 | 11 | YES (tcp) | binary burst, no prefix |
| cmd/windows | staged | shell | tcp_uuid | 8 | YES (tcp) | LE length prefix (shell stage) |
| cmd/windows | staged | shell | udp | 3 | YES (udp) | LE length prefix (shell stage) |
| cmd/windows | staged | upexec | tcp | 18 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | upexec | tcp_rc4 | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | upexec | tcp_uuid | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | upexec | udp | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | staged | vncinject | http | 16 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | staged | vncinject | https | 10 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | staged | vncinject | tcp | 26 | YES (tcp) | binary burst, no prefix |
| cmd/windows | staged | vncinject | tcp_rc4 | 11 | YES (tcp) | binary burst, no prefix |
| cmd/windows | staged | vncinject | tcp_uuid | 8 | YES (tcp) | binary burst, no prefix |
| cmd/windows | single | meterpreter | http | 7 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | single | meterpreter | https | 7 | YES (tcp) | HTTPS probe ("It works!") |
| cmd/windows | single | meterpreter | tcp | 13 | YES (tcp) | binary burst, no prefix |
| cmd/windows | single | other | cmdshell | 3 | YES (tcp) | echo <token> probe |
| cmd/windows | single | other | named_pipe | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | other | tcp | 26 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | other | tcp_rc4 | 8 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | other | tcp_uuid | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | shell | cmdshell | 1 | YES (tcp) | echo <token> probe |
| cmd/windows | single | shell | named_pipe | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | shell | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | shell | tcp | 28 | no (silent) | handler waits for client (stageless) |
| cmd/windows | single | shell | tcp_rc4 | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | shell | tcp_ssl | 10 | no (silent) | handler waits for client (stageless) |
| cmd/windows | single | shell | tcp_uuid | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| cmd/windows | single | shell | udp | 1 | YES (udp) | echo <token> probe |
| firefox | single | shell | tcp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| generic | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| java | staged | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| java | staged | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| java | staged | meterpreter | tcp | 1 | YES (tcp) | BE length prefix (jar/dex) |
| java | staged | shell | tcp | 1 | YES (tcp) | BE length prefix |
| java | single | shell | tcp | 2 | YES (tcp) | echo <token> probe |
| linux | staged | meterpreter | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| linux | staged | meterpreter | tcp | 8 | YES (tcp) | LE length prefix (shell stage) |
| linux | staged | meterpreter | tcp_uuid | 1 | YES (tcp) | binary burst, no prefix |
| linux | staged | shell | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| linux | staged | shell | tcp | 8 | YES (tcp) | LE length prefix (shell stage) |
| linux | staged | shell | tcp_uuid | 1 | YES (tcp) | raw /bin/sh shellcode |
| linux | single | meterpreter | http | 9 | YES (tcp) | HTTP probe ("It works!") |
| linux | single | meterpreter | https | 9 | YES (tcp) | HTTPS probe ("It works!") |
| linux | single | meterpreter | tcp | 9 | no (silent) | handler waits for client (stageless) |
| linux | single | other | tcp | 2 | no (silent) | handler waits for client (stageless) |
| linux | single | shell | tcp | 12 | no (silent) | handler waits for client (stageless) |
| mainframe | single | shell | tcp | 1 | no (silent) | handler waits for client (stageless) |
| multi | staged | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| multi | staged | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| netware | staged | shell | tcp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| nodejs | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| nodejs | single | shell | tcp_ssl | 1 | YES (tcp) | echo <token> probe |
| osx | staged | meterpreter | tcp | 2 | YES (tcp) | binary burst, no prefix |
| osx | staged | meterpreter | tcp_uuid | 1 | YES (tcp) | binary burst, no prefix |
| osx | staged | shell | tcp | 2 | YES (tcp) | LE length prefix (shell stage) |
| osx | single | meterpreter | http | 2 | YES (tcp) | HTTP probe ("It works!") |
| osx | single | meterpreter | https | 2 | YES (tcp) | HTTPS probe ("It works!") |
| osx | single | meterpreter | tcp | 2 | YES (tcp) | binary burst, no prefix |
| osx | single | other | tcp | 4 | YES (tcp) | LE length prefix (metsrv) |
| osx | single | other | tcp_uuid | 1 | YES (tcp) | raw /bin/sh shellcode |
| osx | single | shell | tcp | 7 | no (silent) | handler waits for client (stageless) |
| php | staged | meterpreter | tcp | 1 | YES (tcp) | BE length prefix (php) |
| php | staged | meterpreter | tcp_uuid | 1 | YES (tcp) | BE length prefix (php) |
| php | single | meterpreter | tcp | 1 | YES (tcp) | binary burst, no prefix |
| php | single | other | cmdshell | 19 | YES (tcp) | echo <token> probe |
| php | single | other | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| php | single | other | tcp | 5 | no (silent) | handler waits for client (stageless) |
| php | single | other | tcp_ssl | 6 | YES (tcp) | echo <token> probe |
| python | staged | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| python | staged | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| python | staged | meterpreter | tcp | 1 | YES (tcp) | BE length prefix (base64/zlib) |
| python | staged | meterpreter | tcp_ssl | 1 | YES (tcp) | BE length prefix (base64/zlib) |
| python | staged | meterpreter | tcp_uuid | 1 | YES (tcp) | BE length prefix (base64/zlib) |
| python | single | meterpreter | http | 1 | YES (tcp) | HTTP probe ("It works!") |
| python | single | meterpreter | https | 1 | YES (tcp) | HTTPS probe ("It works!") |
| python | single | meterpreter | tcp | 1 | YES (tcp) | binary burst, no prefix |
| python | single | other | tcp | 1 | no (silent) | handler waits for client (stageless) |
| python | single | shell | sctp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| python | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| python | single | shell | tcp_ssl | 1 | YES (tcp) | echo <token> probe |
| python | single | shell | udp | 1 | YES (udp) | echo <token> probe |
| r | single | shell | tcp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| ruby | single | other | tcp | 1 | no (silent) | handler waits for client (stageless) |
| ruby | single | shell | tcp | 1 | YES (tcp) | echo <token> probe |
| ruby | single | shell | tcp_ssl | 1 | YES (tcp) | echo <token> probe |
| solaris | single | shell | tcp | 2 | YES (tcp) | echo <token> probe |
| windows | staged | custom | http | 4 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | https | 4 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | named_pipe | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | tcp | 8 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | tcp_rc4 | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | tcp_uuid | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | custom | udp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | dllinject | http | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | dllinject | tcp | 7 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | dllinject | tcp_rc4 | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | dllinject | tcp_uuid | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | meterpreter | http | 4 | YES (tcp) | HTTP probe ("It works!") |
| windows | staged | meterpreter | https | 4 | YES (tcp) | HTTPS probe ("It works!") |
| windows | staged | meterpreter | named_pipe | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | meterpreter | tcp | 8 | YES (tcp) | HTTP probe ("It works!") |
| windows | staged | meterpreter | tcp_rc4 | 3 | YES (tcp) | binary burst, no prefix |
| windows | staged | meterpreter | tcp_uuid | 2 | YES (tcp) | LE length prefix (metsrv) |
| windows | staged | patchupdllinject | tcp | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | patchupdllinject | tcp_rc4 | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | patchupdllinject | tcp_uuid | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | patchupmeterpreter | tcp | 6 | YES (tcp) | LE length prefix (shell stage) |
| windows | staged | patchupmeterpreter | tcp_rc4 | 2 | YES (tcp) | binary burst, no prefix |
| windows | staged | patchupmeterpreter | tcp_uuid | 1 | YES (tcp) | LE length prefix (shell stage) |
| windows | staged | shell | tcp | 7 | YES (tcp) | LE length prefix (shell stage) |
| windows | staged | shell | tcp_rc4 | 3 | no (silent) | handler waits for client (stageless) |
| windows | staged | shell | tcp_uuid | 2 | YES (tcp) | LE length prefix (shell stage) |
| windows | staged | shell | udp | 1 | YES (udp) | LE length prefix (shell stage) |
| windows | staged | upexec | tcp | 6 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | upexec | tcp_rc4 | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | upexec | tcp_uuid | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | upexec | udp | 1 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | staged | vncinject | http | 4 | YES (tcp) | HTTP probe ("It works!") |
| windows | staged | vncinject | https | 2 | no (silent) | handler waits for client (stageless) |
| windows | staged | vncinject | tcp | 8 | YES (tcp) | HTTP probe ("It works!") |
| windows | staged | vncinject | tcp_rc4 | 3 | no (silent) | handler waits for client (stageless) |
| windows | staged | vncinject | tcp_uuid | 2 | no (silent) | handler waits for client (stageless) |
| windows | single | meterpreter | http | 2 | YES (tcp) | HTTP probe ("It works!") |
| windows | single | meterpreter | https | 2 | YES (tcp) | HTTPS probe ("It works!") |
| windows | single | meterpreter | tcp | 4 | YES (tcp) | binary burst, no prefix |
| windows | single | other | named_pipe | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | single | other | tcp | 10 | YES (tcp) | binary burst, no prefix |
| windows | single | other | tcp_rc4 | 3 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | single | other | tcp_uuid | 2 | n/t (no listener) | did not bind (needs opts / non-TCP / exotic OS) |
| windows | single | shell | tcp | 4 | no (silent) | handler waits for client (stageless) |
| windows | single | shell | tcp_ssl | 2 | no (silent) | handler waits for client (stageless) |
