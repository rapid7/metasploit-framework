---
applyTo: "modules/**/*.rb"
---

# Module Development Instructions

## Structure Order

1. `# frozen_string_literal: true`
2. Header comment block
3. `class MetasploitModule < Msf::Exploit::Remote` (or `Msf::Auxiliary`, `Msf::Post`)
4. `Rank = ExcellentRanking` (exploits only)
5. Protocol mixins (`include Msf::Exploit::Remote::HttpClient`, etc.)
6. Utility mixins (`include Msf::Exploit::FileDropper`, etc.)
7. `prepend Msf::Exploit::Remote::AutoCheck` — ALWAYS LAST
8. `def initialize` with `update_info`
9. `def check` (when possible)
10. `def exploit` or `def run`

## Required Metadata

- `'Name'` — Vendor Product Vulnerability Type
- `'Description'` — use `%q{}` for multi-line
- `'Author'` — array with role comments
- `'License'` — `MSF_LICENSE`
- `'References'` — `[['CVE', '...'], ['URL', '...']]`
- `'DisclosureDate'` — required for exploits
- `'Notes'` — required with `Stability`, `SideEffects`, `Reliability`

## Notes Hash Values

- **Stability:** `CRASH_SAFE`, `CRASH_SERVICE_RESTARTS`, `CRASH_SERVICE_DOWN`, `CRASH_OS_RESTARTS`, `CRASH_OS_DOWN`
- **SideEffects:** `IOC_IN_LOGS`, `ARTIFACTS_ON_DISK`, `CONFIG_CHANGES`, `ACCOUNT_LOCKOUTS`, `SCREEN_EFFECTS`
- **Reliability:** `REPEATABLE_SESSION`, `FIRST_ATTEMPT_FAIL`, `UNRELIABLE_SESSION`, `EVENT_DEPENDENT`

## Payload Selection

- Command execution only → `ARCH_CMD` payloads
- Only HTTP outbound (curl/wget) → fetch payload
- File write possible → dropper/EXE (`Msf::Exploit::EXE`)
- Multi-step upload → `Msf::Exploit::CmdStager` (but prefer fetch when possible)

## Do NOT

- Set `DefaultOptions => { 'PAYLOAD' => '...' }` unless platform-locked
- Use `cmd_exec` with string interpolation — use `create_process(exe, args: [])`
- Use `HttpFingerprint` — implement a proper `check` method instead
- Use `include` for AutoCheck — must be `prepend`
- Return bare `CheckCode::Safe` without a reason string
- Use `JSON.parse(res.body)` — use `res.get_json_document`
- Print `"#{ip}:#{port}"` — use `Rex::Socket.to_authority(ip, port)`

## Auxiliary Modules

- Inherit from `Msf::Auxiliary` (not `Msf::Exploit::Remote`)
- Use `def run` (not `def exploit`)
- Use `report_service` / `report_vuln` for findings

## Post Modules

- Inherit from `Msf::Post`
- Declare `'SessionTypes' => ['meterpreter', 'shell']`
- Use `create_process` for command execution (not `cmd_exec` with args)
- Use `Msf::OptionalSession` for modules that work with or without sessions
