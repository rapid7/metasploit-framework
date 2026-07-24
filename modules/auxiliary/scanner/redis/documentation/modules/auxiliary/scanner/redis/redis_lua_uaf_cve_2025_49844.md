## Vulnerable Application

This module detects whether a remote Redis (or Redis-protocol compatible service such as
Valkey) is running a version affected by CVE-2025-49844, publicly referred to as
"RediShell". This is a critical (CVSS 10.0 / 9.9 depending on scoring source)
use-after-free vulnerability in the Lua scripting garbage collector that can allow an
authenticated user to send a specially crafted Lua script and achieve remote code
execution on the Redis host.

The problem exists in all Redis versions with Lua scripting enabled (Lua scripting has
shipped since Redis 2.6). It is fixed in:

- 6.2.20
- 7.2.11
- 7.4.6
- 8.0.4
- 8.2.2

Official advisory: https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q

**This module is detection-only.** It does not attempt to trigger the use-after-free
condition or execute arbitrary code on the target. It fingerprints the Redis version via
`INFO server`, compares it against the officially patched release for that branch, and
(optionally) sends a harmless `EVAL "return 1" 0` probe to confirm whether Lua scripting
is actually reachable (as opposed to blocked by an ACL), since that materially affects
real-world exploitability.

### Setting up a vulnerable environment for testing

```
docker run -p 6379:6379 redis:7.4.2
```

Any Redis image at or below the patched version for its branch (see list above) with Lua
scripting enabled and no ACL restriction on EVAL/EVALSHA will trigger a `VULNERABLE`
result.

To test the "blocked" code path, restrict scripting via ACL before running the module:

```
redis-cli ACL SETUSER default -eval -evalsha -eval_ro -evalsha_ro -fcall -fcall_ro -function
```

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/scanner/redis/redis_lua_uaf_cve_2025_49844`
3. `set RHOSTS <target>`
4. `set PASSWORD <password>` (only if the target requires Redis AUTH)
5. `run`

## Options

**CHECK_LUA**

Boolean, default `true`. When enabled, sends a harmless `EVAL "return 1" 0` command
after the version check to confirm whether Lua scripting is actually invocable on the
target. Disable this if you only want a version-based check with zero additional
commands sent.

**PASSWORD**

Inherited from `Msf::Auxiliary::Redis`. Set this if the target requires `AUTH`.

## Scenarios

### Redis 7.4.2 (Docker, default config, no ACL restriction)

```
msf6 auxiliary(scanner/redis/redis_lua_uaf_cve_2025_49844) > run

[*] 127.0.0.1:6379 - Scanned 1 of 1 hosts
[+] 127.0.0.1:6379 - Redis 7.4.2: VULNERABLE to CVE-2025-49844 (RediShell) - unpatched branch and Lua EVAL is reachable
[*] Auxiliary module execution completed
```

### Redis 8.2.2 (patched)

```
msf6 auxiliary(scanner/redis/redis_lua_uaf_cve_2025_49844) > run

[*] 127.0.0.1:6379 - Scanned 1 of 1 hosts
[*] 127.0.0.1:6379 - Redis 8.2.2: patched against CVE-2025-49844
[*] Auxiliary module execution completed
```

### Redis 7.4.2 with EVAL restricted via ACL

```
msf6 auxiliary(scanner/redis/redis_lua_uaf_cve_2025_49844) > run

[*] 127.0.0.1:6379 - Scanned 1 of 1 hosts
[!] 127.0.0.1:6379 - Redis 7.4.2: unpatched branch for CVE-2025-49844, but EVAL/EVALSHA look blocked (ACL?) - real-world risk reduced
[*] Auxiliary module execution completed
```
