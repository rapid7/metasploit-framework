# AI Agent Instructions for Metasploit Framework

This file defines the shared repository instructions for coding and review agents. Apply [.rubocop.yml](.rubocop.yml) when linting Ruby. CodeRabbit loads this file repository-wide. `CONTRIBUTING.md` is written for human contributors.

## Project Overview

Metasploit Framework is an open-source penetration testing and exploitation framework written in Ruby. It provides infrastructure for developing, testing, and executing exploit code against remote targets.

## Project Structure

- `modules/` — Metasploit modules (exploits, auxiliary, post, payloads, encoders, evasion, nops)
- `lib/msf/` — Core framework library code
- `lib/rex/` — Rex (Ruby Exploitation) library
- `lib/metasploit/` — Metasploit namespace libraries
- `data/` — Data files used by modules (wordlists, templates, binaries)
- `spec/` — RSpec test suite
- `tools/` — Developer and operational tools
- `plugins/` — msfconsole plugins
- `scripts/` — Example automation scripts
- `documentation/modules/` — Markdown documentation for Metasploit modules

## Coding Conventions

- Discover the current Ruby version from `.ruby-version` and supported versions from the gemspec.
- Follow `.rubocop.yml`; lint changed Ruby and run `ruby tools/dev/msftidy.rb <module>` for changed modules. Avoid unrelated style sweeps.
- Add `# frozen_string_literal: true` to new library files only; use `String.new` for mutable buffers. Do not add it to module/spec files, which mutate buffers extensively. Existing comments may remain; `Style/FrozenStringLiteralComment` is disabled project-wide.
- Keep lines readable; no line-length limit is enforced. Use `%q{}` for long multiline descriptions; multiline block comments may hold embedded payload/code snippets.
- Avoid accessor-style `get_`/`set_` names. Parameter names require at least two characters, except established crypto abbreviations.
- Successful returns must keep one type/shape on cached and uncached paths. Document exceptions or unambiguous failure sentinels and handle them in all callers.
- Use `include?`, `start_with?`, and `end_with?` for literal string checks; reserve regexes for patterns and use noncapturing `(?:...)` groups when captures are unused.
- Prefer guards and helpers over deep nesting; separate checks needing distinct failure reasons.
- Avoid mutable global/class variables. Keep callback state in instance variables and method-local state in locals.
- Remove unused code/options/mixins, unreachable/obsolete branches, and debugging remnants. Before removing library code, check public API and external consumers.
- Call `super` from overridden cleanup methods to preserve parent connection/session cleanup.

## Reuse Before Implementing

Search before implementing; stop at the first fit:

1. Reuse Framework libraries and mixins in `lib/msf/`, `lib/rex/`, and `lib/metasploit/`.
2. Extend an existing helper that nearly fits rather than duplicating it.
3. Reuse a gem already listed in `Gemfile` or `metasploit-framework.gemspec`.
4. If none fits, explain the gap. Evaluate a well-maintained new gem only when the user requests it; do not add dependencies without direct instruction.
5. Otherwise implement reusable logic under `lib/` when practical, separate from module code.

For new modules, also check existing modules and open PRs for duplicate functionality. Keep shared defaults, ports, addresses, protocol values, lookup tables, and duplicated behavior in one component-owned constant/helper used by every consumer.

## Backward Compatibility

Public library methods, module names/options/aliases, and documented return shapes are compatibility surfaces. Search repository and known external consumers before changes. Prefer aliases, wrappers, module deprecation/replacement metadata, and compatible defaults. Document unavoidable breaking impacts and migration steps.

## Module Structure Templates

### Exploit Module Template

- Start with the standard Metasploit source header, the appropriate `Msf::Exploit::Remote` or `Msf::Exploit::Local` superclass, and an exploit-only `Rank`.
- Order mixins as specified below, then `initialize(info = {})` calling `super(update_info(info, ...))`, `check` when supported, and `exploit`.
- Metadata includes `Name` (vendor, product, vulnerability type), ASCII `Description` using `%q{}`, authors with role comments, `MSF_LICENSE`, advisory/CVE references, `Targets`, `DefaultTarget`, `DisclosureDate`, and `Notes`.
- Each target has a display name and applicable `Platform`, `Arch`, and delivery `Type` (such as `:cmd`, `:dropper`, or `:psh_stager`). `DefaultTarget` indexes that array; an automatic first target uses index `0`.

### Auxiliary Module Template

- Inherit from `Msf::Auxiliary`; use `run` instead of `exploit` and omit `Rank`.
- Initialize with `super(update_info(info, ...))`; include name, description, author, license, references, and Notes. Register module-specific options after `super`.
- Include the needed protocol and reporting mixins; prepend AutoCheck last when a check is implemented. Return qualified `Exploit::CheckCode` values with reasons.
- Report discovered services and vulnerabilities with `report_service` and `report_vuln`.

### Post Module Template

- Inherit from `Msf::Post`; include the needed file and platform/system mixins and implement `run`.
- Initialize with `super(update_info(info, ...))`; include name, description, author, license, `Platform`, supported `SessionTypes`, and Notes.
- Access the session through `session`; use APIs such as `create_process`, `file_exist?`, and `read_file`. Declare only session types whose APIs the module handles.

Before creating or reviewing a module, read the relevant source example below and nearby modules using the same protocol, platform, and session APIs:

| Category | Existing source examples |
|---|---|
| Remote exploit | [TCP](modules/exploits/example.rb), [web application](modules/exploits/example_webapp.rb) |
| Local exploit | [Linux privilege escalation](modules/exploits/example_linux_priv_esc.rb) |
| Auxiliary | [Actions and custom commands](modules/auxiliary/example.rb), [UDP scanner](modules/auxiliary/scanner/udp/example.rb) |
| Post | [Cross-platform environment gathering](modules/post/multi/gather/env.rb) |

For other module types, inspect an existing module in the matching subtree and its generator template. Use the module generator for new source and documentation skeletons; its maintained category templates live in [lib/tasks/templates](lib/tasks/templates). Examples illustrate structure and APIs, but may contain intentional stubs or legacy patterns. Follow the current rules in this file; do not copy placeholder metadata, legacy APIs, or simulated check results into a real module.

### Notes Hash Reference

The `Notes` hash declares the module's operational characteristics:

| Key | Values | Meaning |
|-----|--------|---------|
| `Stability` | `CRASH_SAFE`, `CRASH_SERVICE_RESTARTS`, `CRASH_SERVICE_DOWN`, `CRASH_OS_RESTARTS`, `CRASH_OS_DOWN` | Impact on target stability |
| `SideEffects` | `IOC_IN_LOGS`, `ARTIFACTS_ON_DISK`, `CONFIG_CHANGES`, `ACCOUNT_LOCKOUTS`, `SCREEN_EFFECTS`, `AUDIO_EFFECTS`, `PHYSICAL_EFFECTS` | Observable traces left on target |
| `Reliability` | `REPEATABLE_SESSION`, `FIRST_ATTEMPT_FAIL`, `UNRELIABLE_SESSION`, `EVENT_DEPENDENT` | How reliably the module succeeds |

See also: [`lib/msf/core/constants.rb`](lib/msf/core/constants.rb) for the full list of valid values with descriptions.

**Which module types require Notes:**

| Module Type | Notes Required? | Enforced By |
|-------------|----------------|-------------|
| Exploit | **Yes** | msftidy + rubocop (`Lint/ModuleEnforceNotes`) |
| Auxiliary | **Yes** | rubocop (`Lint/ModuleEnforceNotes`) |
| Post | **Yes** | rubocop (`Lint/ModuleEnforceNotes`) |
| Evasion | No | — |
| Payload | No | — |
| Encoder | No | — |
| Nop | No | — |

The same `Stability`, `SideEffects`, and `Reliability` constants apply uniformly — there are no type-specific values. Payloads, encoders, and nops don't use Notes because they don't independently interact with targets.

### Metadata Source Reference

Metadata examples are not exhaustive. Consult these source files for the full set:

| Field | Source File | Details |
|-------|------------|-------|
| Platform | [`lib/msf/core/module/platform.rb`](lib/msf/core/module/platform.rb) | Class hierarchy — use the lowercase short name (e.g. `'linux'`, `'win'`, `'osx'`) |
| Arch | [`rex-arch` gem](https://github.com/rapid7/rex-arch/blob/master/lib/rex/arch.rb) | Constants like `ARCH_CMD`, `ARCH_X86`, `ARCH_X64`, `ARCH_PHP` etc. |
| Stability / SideEffects / Reliability | [`lib/msf/core/constants.rb`](lib/msf/core/constants.rb) | All valid Notes hash values with descriptions |
| Rank | [`lib/msf/core/constants.rb`](lib/msf/core/constants.rb) | `ManualRanking` through `ExcellentRanking` |
| CheckCode | [`lib/msf/core/exploit.rb`](lib/msf/core/exploit.rb) (line ~52) | `Vulnerable`, `Appears`, `Safe`, `Detected`, `Unknown`, `Unsupported` |

### Mixin Ordering

Follow this order for includes and prepends in module classes:

1. **Protocol mixins** — `Msf::Exploit::Remote::HttpClient`, `RubySMB`, `Msf::Exploit::Remote::Udp`, etc.
2. **Utility/feature mixins** — `Msf::Exploit::FileDropper`, `Msf::Exploit::CmdStager`, `Msf::Exploit::EXE`, etc.
3. **Reporting mixins** — `Msf::Auxiliary::Report`
4. **Post mixins** (if needed) — `Msf::Post::File`, `Msf::Post::Linux::Priv`, etc.
5. **`prepend Msf::Exploit::Remote::AutoCheck`** — always last, after all includes

AutoCheck must use `prepend`, not `include` (the module raises `NotImplementedError` if included). It wraps the `exploit`/`run` method to automatically call `check` before exploitation.

## Module Development

### Metadata and Structure

- Scaffold modules and documentation with `bundle exec rake 'msf:generate[TYPE,PATH]'`, e.g. `rake 'msf:generate[exploit,linux/http/my_vuln,linux,x64]'`. Set `MSF_MOD_AUTHOR`/`MSF_MOD_CVE`; use `MSF_DRY_RUN=1` to preview and `bundle exec rake msf:generate:types` to list types.
- Resolve generated `TODO:`, `PLACEHOLDER:`, stub descriptions/methods, and empty Notes arrays before submitting.
- Prefer Ruby; Go/Python modules' external runtimes lack parts of the Framework API, including pivoting.
- Prefer hashes over arrays for return values and kwargs for extensible reusable APIs.
- Use one file per module in the appropriate `modules/` subtree; actions/targets may be preferable to separate modules.
- Exploits require `DisclosureDate` and an exploit-only `Rank`; auxiliary, post, login-scanner, and other non-exploit modules must not declare Rank.
- Exploit/auxiliary/post modules require Stability, SideEffects, and Reliability Notes. License new code with `MSF_LICENSE`, defined in `lib/msf/core/constants.rb`.
- Give every Author an inline role comment distinguishing discovery, research, PoC, and module implementation. Reference authoritative advisories and public PoCs that informed implementation.
- Determine affected and fixed releases, including separate branch fixes; keep description, targets, check logic, and docs consistent. Descriptions must be ASCII.
- New modules require matching Markdown under `documentation/modules` using `documentation/modules/module_doc_template.md`, with reproducible vulnerable-target setup. Put Docker/Compose lab commands in Markdown rather than separate Docker files. Scenarios must be filled by a human.
- Module documentation must include `Vulnerable Application` (affected/fixed versions and setup), `Verification Steps` (numbered steps with expected outcomes), and `Scenarios` (human-written real console output). Do not invent scenario results.
- Document only specialist options under `###`; write `No specific options` when none apply. Keep scenario output current; use `run verbose=true` when useful for diagnosis/reproduction.
- Explain nonobvious constants, salts, offsets, fixed names/paths, double encoding, hardcoding, and compatibility workarounds nearby; include sources when available.
- A lone ACTION can usually be omitted.

### Payloads and Targets

- When possible don't set a default payload (`DefaultOptions` with `'PAYLOAD'`) in modules — let the framework choose the most appropriate payload automatically; only hardcode one when the module genuinely works with a single specific payload
- Define bad characters instead of explicitly base-64 encoding payloads
- Randomize application-visible names, labels, and identifiers when practical to reduce exploit signatures. Use `Faker` for realistic values and `Rex::RandomIdentifier::Generator` with the correct runtime language for identifiers embedded in generated code; don't generate identifiers that can be language keywords
- Don't check the number of sessions at the end of an exploit and report success based on that — not all payloads open sessions
- Don't submit any kind of opaque binary blob — everything must include source code and build instructions

**Payload selection guidance:**

| Scenario | Approach |
|----------|----------|
| Only command execution available (no file write) | Use `ARCH_CMD` payloads |
| Only HTTP(S) outbound (curl/wget available) | Use fetch payload (`Msf::Exploit::Remote::HttpServer` + fetch handler) |
| File write possible on target | Use dropper/EXE payload (`Msf::Exploit::EXE`) |
| Full command stager needed (multi-step upload) | Use `Msf::Exploit::CmdStager` — but prefer fetch when only download mechanisms are available |

### File and Network Operations

- For created target artifacts, include FileDropper and register each successfully created file/directory with `register_file_for_cleanup`/`register_dir_for_cleanup`. Let it handle session cleanup unless the target needs special removal.
- For non-file state or cleanup without a session, keep minimal instance state and use guarded cleanup, preferably through the target API/vulnerability. Report cleanup/disconnect errors at suitable verbosity, continue the chain, and never `fail_with` in cleanup.
- Check that a file exists before opening it.
- Format intentionally printed hosts/ports with `Rex::Socket.to_authority(ip, port)` for IPv6. This is separate from avoiding duplicate target prefixes supplied by mixins.
- Use TEST-NET-1 (`192.0.2.0/24`) for example addresses in specs; private/local IPs are acceptable in documentation lab scenarios.

### Output and Reporting

- All `print_*` calls should start with a capital letter
- Failure and error messages should identify the operation that failed, not only the returned status or exception. When useful, tell the operator which prerequisite, target state, or datastore option can resolve the problem. Do not silently discard rescued cleanup or disconnect errors; report them at an appropriate verbosity
- Call `report_service` when a service can be reported
- Call `report_vuln` when a vulnerability can be reported
- Persist credentials that a module discovers, validates, or creates using `store_valid_credential` or the appropriate credential-reporting API. Include the relevant service, origin, status, and proof context rather than only printing the credential
- When creating a fake account / username use the `Faker` gem (e.g. `Faker::Internet.username`) not `Rex::Text.rand_text_alphanumeric`

### Module Error Handling

- Rescue only the specific exceptions an operation is expected to raise. Convert expected module failures into an appropriate `CheckCode` from `check`, or `fail_with` from `run`/`exploit`; keep operator output concise and preserve exception details for developers with `elog('Context', error: e)`. Do not print raw backtraces or silently discard an exception by returning `nil`
- Treat helper, parser, and dependency returns as nullable unless their contract guarantees a value. Handle a failure sentinel before dereferencing or otherwise consuming the result
- Choose the narrowest applicable `Failure::*` value. Reserve `Failure::Unknown` for failures without a more useful root cause

### Session and Post-Exploitation

- Use `create_process(executable, args: [], time_out: 15, opts: {})` instead of the deprecated `cmd_exec` with separate arguments
- Use `Msf::OptionalSession` for modules that work both with and without an existing session (e.g. local exploits that can also run standalone)
- Use the module mixin APIs — don't reinvent the wheel (see the Reuse Before Implementing section)
- Declare only session types the module actually supports. When functional testing is requested, cover each declared `SessionTypes` value. Meterpreter, command shell, and PowerShell sessions expose different APIs, quoting behavior, and output; payload compatibility alone does not prove post-module compatibility
- When functional testing is requested, cover distinct execution paths across targets, actions, platforms, payload delivery families, and authentication modes
- When state-changing functional testing is authorized, verify that per-run state resets and cleanup permit a second execution

### Internationalization Considerations

- When checking for a string in a response — will it always be in English?
- Ensure hardcoded strings being regex'ed will be consistent across multiple versions

## Check Methods

- Return only reason-bearing CheckCode values from `check`; never raise or call `fail_with`. Handle expected exceptions and ensure shared helpers cannot bypass that contract.
- Avoid false positives on unrelated products/services. Extract versions with precise regexes or HTML CSS selectors, not generic matches such as `href .*`.
- Use `Rex::Version` whenever gathering, returning, or comparing a supported version format. Research the minimum vulnerable release and mark earlier versions Safe; account for fixed release branches.
- `CheckCode::Vulnerable` requires hard evidence from using the bug, such as command output, a timed sleep, or reading a file. Do not prove it through denial of service. Passive version/banner/resource detection supports `CheckCode::Appears`.
- Every result needs a human-readable reason, e.g. `CheckCode::Safe("Target is running patched version #{version}")`; no bare constants or empty calls.
- Share stable discovery/authentication between check and run/exploit; cache per instance when it avoids duplicate target operations.
- Initialize state needed by run/exploit even with AutoCheck disabled; never assume check already ran.
- Prefer `prepend Msf::Exploit::Remote::AutoCheck` over manually invoking check; follow the Mixin Ordering rules.

## Library Code

When writing or modifying code in `lib/`:

### Error Handling
- Use specific error classes (`Rex::RuntimeError`, `Rex::ConnectionError`, `ArgumentError`, `Rex::TimeoutError`) — never `raise "bare string"` which makes targeted rescue impossible
- Use `rescue StandardError => e` or a more specific class so the handled exception and its context are explicit. Bare `rescue` also catches `StandardError`; avoid it here for clarity. Do not rescue `Exception`, which also catches signals and exits.
- Propagate errors with context: `raise Rex::ConnectionError, "Failed to connect to #{host}: #{e.message}"`

### Documentation and Style
- Add YARD `@param` and `@return` tags to all public methods
- Link to the specification or RFC when implementing binary/protocol parsers
- Note: new library files also need `# frozen_string_literal: true`, and the no-`get_`/`set_` accessor convention applies here too (see Coding Conventions)

### Quality
- Write focused RSpec tests for library behavior changes (see the Testing section)
- Follow [Better Specs](https://www.betterspecs.org/) conventions
- Keep PRs focused — small fixes are easier to review
- Any new hash cracking implementations require adding a test hash to `tools/dev/hash_cracker_validator.rb` and ensuring that passes without error

## Testing

- Tests live in `spec/` mirroring the `lib/` structure
- Run a single spec file: `bundle exec rspec spec/path/to/spec.rb`
- Run a single example by line: `bundle exec rspec spec/path/to/spec.rb:42`
- Run the full suite only when explicitly requested: `bundle exec rake spec`
- Module functional tests live under `spec/modules/` and test end-to-end behavior, including `check` and `exploit`/`run` methods
- Require and run relevant specs for library behavior changes. Verify other changes with proportionate syntax, lint, output, or behavior checks; CI and build changes do not require automated tests unless requested. Do not require module or application tests unless requested.
- Use `described_class`, `let`/`let!` for setup, and `before` for side effects where consistent with the existing suite. Keep examples focused, deterministic, and example-based; avoid randomized/property-based loops.
- Prefer one expectation per example when practical.
- Use explicit test data and TEST-NET-1 (`192.0.2.0/24`) for example addresses. Existing Faker usage for account data must not make an example nondeterministic.
- When an example specifically needs generated random data, use `Rex::Text.rand_text_alphanumeric` for strings and `Faker` for usernames/accounts; keep the example deterministic.
- Cover changed public inputs/outputs, error contracts, parsing (including round-trip encode/decode), and version boundaries when relevant.
- Derive output expectations from real captures rather than assumptions. Prefer stable structural/anchored matches and include meaningful negative cases.
- Report checks actually run, results, and limitations; distinguish pre-existing failures.

## Preferred Libraries

- Use the `RubySMB` library for SMB operations
- Use `Rex::Stopwatch.elapsed_time` to track elapsed time
- Use the `Rex::MIME::Message` class for MIME messages instead of hardcoding XML
- Use `Rex::RandomIdentifier::Generator` with the target runtime language for identifiers embedded in generated code.
- Use `Msf::Exploit::SQLi` when exploiting SQL injection vulnerabilities

## Common Patterns

### Options Registration

```ruby
register_options([
  OptString.new('TARGETURI', [true, 'Base path to the application', '/']),
  OptInt.new('TIMEOUT', [true, 'Request timeout in seconds', 10]),
  OptBool.new('SSL', [false, 'Use SSL/TLS', false])
])

register_advanced_options([
  OptString.new('UserAgent', [false, 'Custom User-Agent header'])
])
```

- Use `SCREAMING_SNAKE_CASE` for standard option names and `CamelCase` for advanced option names
- Access options via `datastore['OPTION_NAME']`
- Do not modify datastore options during module execution. Keep normalized, derived, or runtime values in separate local or instance variables so retries and cleanup preserve the operator's configuration
- Model each value with the most specific option type: use `OptEnum` for a fixed set, `OptInt`/`OptPort` for numeric values, `OptBool` for booleans, `OptPath` for local paths, and `OptAddress` for addresses. Requiredness and defaults must reflect actual runtime behavior; add validation for constrained strings and use `conditions:` for action- or mode-specific options. Put specialist or rarely changed controls in advanced options
- Do not re-register an option already owned by a mixin solely to change its default. Set the default through `DefaultOptions` or the module info hash; re-register only when intentionally providing a more specific description, validation, or constraint

### Console Output

- Use `print_status`, `print_good`, `print_error`, and `print_warning`; start messages with a capital letter.
- Use `vprint_*` (enabled with `VERBOSE true`) for routine target/credential attempts, expected negatives, and diagnostics. Reserve normal errors/warnings for actionable conditions.
- Tcp and scanner mixins prepend host:port through `print_prefix`; do not duplicate `#{peer}`, `#{rhost}:#{rport}`, or authority strings in messages. `Lint/RedundantPeerInPrint` is syntactic and may false-positive on HttpClient-only modules.
- HttpClient alone does not include Tcp or add target host:port. Its default `Msf::Module::UI::Message#print_prefix` contains only optional timestamp/module name. A manual target prefix there is not redundant, though many modules omit it for consistency; inspect the actual mixin chain.

### HTTP Response Handling

```ruby
res = send_request_cgi(
  'method' => 'GET',
  'uri' => normalize_uri(target_uri.path, 'api', 'version')
)

fail_with(Failure::Unreachable, 'Target did not respond') unless res
fail_with(Failure::UnexpectedReply, "Unexpected status: #{res.code}") unless res.code == 200

json = res.get_json_document
fail_with(Failure::UnexpectedReply, 'Response is not valid JSON') if json.empty?

# For HTML parsing:
html = res.get_html_document
version = html.at_css('meta[name="version"]')&.[]('content')
```

- Always use `res.get_json_document` — never `JSON.parse(res.body)`
- Use `res.get_html_document` with CSS selectors for HTML parsing
- Check `res` for nil (target didn't respond) before accessing `.code` or `.body`
- Use `fail_with(Failure::*, 'reason')` for error conditions in `exploit`/`run`
- Join request-path components with `normalize_uri` rather than manual string concatenation. Use `full_uri` when generating an absolute URL so the scheme, non-default port, virtual host, and IPv6 authority are formatted correctly; keep query parameters in `vars_get`/`vars_post` instead of embedding them in path components
- Users can override the `send_request_cgi` default timeout through the mixin's `HttpClientTimeout`. Omit per-request timeout values unless the operation requires different behavior. When it does, the distinct timeout must be user-configurable and its purpose must be explained

### Network Operations

- Use `send_request_cgi` for HTTP requests and `connect` / `disconnect` for TCP socket operations
- Use the `srvhost` method to access the server host — don't use `datastore['SRVHOST']` directly (enforced by `Lint/DatastoreSrvhostUsage` cop)
- For eventually consistent operations, use `Msf::Exploit::Retry.retry_until_truthy` or the appropriate bounded polling helper with incremental backoff. Avoid unconditional sleeps and hand-written attempt loops so fast targets continue immediately while slow targets retain sufficient time

## Legacy Patterns (Migration Guidance)

Modernize these patterns when touching existing code; the detailed API rules above still apply:

| Legacy pattern | Replacement |
|---|---|
| Manual target prefix with a Tcp/scanner mixin | Let `print_prefix` supply it; account for the HttpClient-only exception |
| `HttpFingerprint = { :pattern => [...] }` | Check method plus prepended AutoCheck |
| `cmd_exec("command #{input}")` or `cmd_exec(cmd, args_string, timeout)` | `create_process(cmd, args: [input], time_out: timeout)`; separate arguments to avoid injection; `Lint/DetectOutdatedCmdExecApi` flags the old multi-argument API |
| DefaultOptions `PAYLOAD` | Automatic payload selection, except genuinely single-payload modules |
| Included AutoCheck or manual check in exploit | Prepend AutoCheck; include raises `NotImplementedError` |
| Bare rescue or string raise in libraries | Explicit expected rescue class/context and a specific exception class |

### Modernizing Existing Modules

For an existing module with check, adding `prepend Msf::Exploit::Remote::AutoCheck` after the includes enables automatic check-before-exploit. It aborts on a nonvulnerable target unless the operator uses `set ForceExploit true`.

## Code Review Rules

- Review the full PR description and available linked issues, module documentation, and review discussion alongside the diff. Prioritize correctness, security, regressions, compatibility, and reproducible validation of changed behavior.
- Ground each finding in a concrete trigger, affected code, and observable consequence. Distinguish verified behavior from inference; do not flag unrelated pre-existing issues or speculative style preferences.
- Request missing setup/reproduction details when needed: OS and exact target versions, required configuration, lab authentication, and steps showing the original failure for reproducible bug fixes.
- Request missing concrete verification commands/actions, expected observable outcomes, actual results/evidence, or applicable untested limits. For module behavior changes, look for supported check output and run/exploit output. Empty template text, placeholder tasks, generic "tested/works" claims, and generated bot summaries do not establish validation. Explain exactly what is missing and why it matters; do not invent results.
- Accept information already supplied through links or discussion. Do not flag missing headings, checkbox formatting, or unchecked boxes alone. If required linked evidence is inaccessible, explain that limitation instead of claiming the information is absent. Consolidate related PR-information gaps into one actionable request and avoid duplicating existing feedback.
- Keep requests proportional to the change: inspection or preview can validate typo/comment/docs changes. Do not demand a runtime lab for these changes or automated tests for non-library changes; follow the Testing section for library behavior changes.

## Before Submitting

- Keep each PR to one module, bug fix, or cohesive change. Describe what/why, related issues, breaking impacts/migration, useful reviewer pointers, and deferred scope.
- Include applicable setup/recreation steps, tested OS, exact target versions, configuration/lab authentication, and Docker/Vagrant details. Existing issue or module-doc links may supply setup instructions.
- Supply reproducible verification steps/commands, expected observable outcomes, actual results (sanitized console output, screenshots, recording or CI links), and untested limits. Cover relevant success/failure cases; scale checks to typo/comment/docs changes. Do not invent results or human-only Scenarios.
- For new modules, show supported check output and successful execution/exploitation in a controlled lab. Specialized hardware or complex/licensed/multi-service/multi-version environments need sanitized pcap/video/recording evidence; explain unavailable targets. The project accepts demos at `msfdev@metasploit.com`; remove real IPs, credentials, and hostnames. Sending mail requires user authorization.
- Disclose AI tools and their role when preparing a PR; write "None" if unused. Mark unfinished work draft/WIP. Missing descriptions, actionable verification, or evidence cause closure; generic "verify it works" steps are insufficient.
- Check GitHub Actions after submission, inspect failed jobs, and resolve failures relevant to the change. Report actual checks/results and remaining limits.
- After approximately two weeks without a contributor response/code update to a review request, maintainers may finish the PR and retain contributor co-author credit.
- Perform Git mutations only when requested; use a topic branch and requested base, never commit directly to master. Use 50-character commit subjects and wrap bodies at 72 characters.
- Run rubocop and msftidy on changed Ruby/modules, and `ruby tools/dev/msftidy_docs.rb <file>` on changed module docs; resolve new offenses. Include msfconsole demonstrations for observable changes.

## What NOT to Do

- Verify changed code with proportionate syntax, lint, output, or behavior checks. Automated test requirements follow the [Testing](#testing) section.
- Don't include sensitive information (IPs, credentials, API keys, hashes of credentials) in code or docs; local/private IPs are acceptable in documentation lab scenarios
- Don't include more than one module per pull request
- Don't add new scripts to `scripts/` — use post modules instead
- Don't use `pack`/`unpack` with invalid directives (enforced by linter)
