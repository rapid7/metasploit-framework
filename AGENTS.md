# AI Agent Instructions for Metasploit Framework

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

- Ruby (see `.ruby-version` for the current version). Minimum supported: 3.1+
- Follow the project's `.rubocop.yml` configuration — run `rubocop` on changed files before submitting
- Run `ruby tools/dev/msftidy.rb <module_file_path>` to catch common module issues
- `# frozen_string_literal: true` — add to new **library** files (`lib/`); use `String.new` where a mutable string is needed. Do NOT add to module files or spec files (the framework extensively mutates string buffers via instance variables, and the RuboCop cop `Style/FrozenStringLiteralComment` is disabled project-wide). Existing files that already have it are fine to leave
- No enforced line length limit, but keep code readable
- Use `%q{}` for long multi-line strings (curly braces preferred for module descriptions)
- Multiline block comments are acceptable for embedded code snippets/payloads
- Don't use `get_`/`set_` prefixes for accessor methods in new code
- Method parameter names must be at least 2 characters (exception for well-known crypto abbreviations)

## Module Structure Templates

### Exploit Module Template

New exploit modules should follow this canonical structure and ordering:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  # 1. Protocol mixins first
  include Msf::Exploit::Remote::HttpClient
  # 2. Utility/feature mixins second
  include Msf::Exploit::FileDropper
  # 3. Reporting mixins (if needed)
  # include Msf::Auxiliary::Report
  # 4. AutoCheck ALWAYS LAST — must be prepend, not include
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vendor Product Vulnerability Type',
        'Description' => %q{
          Description of the vulnerability and what this module does.
        },
        'Author' => [
          'Discoverer Name', # Vulnerability discovery
          'Module Author'    # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-XXXXX'],
          ['URL', 'https://example.com/advisory']
        ],
        'Targets' => [
          [
            'Automatic',
            {
              'Platform' => ['linux'], # or 'win', 'osx', 'unix', 'php', 'python', 'java'
              'Arch' => [ARCH_CMD], # or ARCH_X86, ARCH_X64, ARCH_PHP, ARCH_JAVA, ARCH_PYTHON, ARCH_ARMLE, ARCH_AARCH64, ARCH_MIPSLE — see rex-arch gem for full list
              'Type' => :cmd # or :dropper, :psh_stager — determines payload delivery
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-01-01',
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE, CRASH_SERVICE_RESTARTS
          'SideEffects' => [], # e.g. IOC_IN_LOGS, ARTIFACTS_ON_DISK
          'Reliability' => [] # e.g. REPEATABLE_SESSION
        }
      )
    )
  end

  def check
    # Always return CheckCode with a reason string
    CheckCode::Safe('Target is not vulnerable')
  end

  def exploit
    # Exploitation logic
  end
end
```

### Auxiliary Module Template

Auxiliary modules use `def run` (not `exploit`) and inherit from `Msf::Auxiliary`:

```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vendor Product Scanner/Gatherer',
        'Description' => %q{
          Description of what this module discovers or does.
        },
        'Author' => ['Author Name'],
        'License' => MSF_LICENSE,
        'References' => [['CVE', '2024-XXXXX']],
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE
          'SideEffects' => [], # e.g. IOC_IN_LOGS
          'Reliability' => [] # e.g. REPEATABLE_SESSION
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def check
    CheckCode::Safe('Target is not affected')
  end

  def run
    # Main logic — use report_service, report_vuln, print_good, etc.
  end
end
```

### Post Module Template

Post modules inherit from `Msf::Post`, require a session, and declare compatible session types:

```ruby
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Platform Subsystem Gather/Action',
        'Description' => %q{
          Description of what this post module does on the target.
        },
        'Author' => ['Author Name'],
        'License' => MSF_LICENSE,
        'Platform' => ['linux'], # or 'win', 'osx', 'unix', 'bsd', 'solaris'
        'SessionTypes' => ['meterpreter', 'shell'], # or just ['meterpreter'] if shell won't work
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE
          'SideEffects' => [], # e.g. ARTIFACTS_ON_DISK, CONFIG_CHANGES
          'Reliability' => []
        }
      )
    )
  end

  def run
    # Use create_process, file_exist?, read_file, etc.
    # Access session via `session` method
  end
end
```

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

The inline comments in the templates above list common values but are **not exhaustive**. Consult these source files for the full set:

| Field | Source File | Notes |
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

### Module Development

#### Metadata and Structure

- Prefer writing modules in Ruby. Go and Python modules are accepted, but their external runtimes don't support the full framework API (e.g. network pivoting). Ruby modules do not have this limitation
- Prefer using hash over an array for return values, and use kwargs for reusable APIs for future extensions
- Before writing a new module, check that there is not an existing module or open pull request that already covers the same functionality
- Each module should be in its own file under the appropriate `modules/` subdirectory. In some scenarios adding module actions or targets is preferred
- Exploits require a `DisclosureDate` field
- Exploits, auxiliary, and post modules require `Notes` with `Stability`, `SideEffects`, and `Reliability`
- License new code with `MSF_LICENSE` (the project default, defined in `lib/msf/core/constants.rb`)
- Module descriptions or documentation should list the range of vulnerable versions and the fixed version of the affected software, when known
- Module descriptions should only use ASCII characters
- New modules require an associated markdown file in the `documentation/modules` folder with the same structure, including steps to set up the vulnerable environment for testing. If a Dockerfile or docker-compose file is used for the test environment, include the setup commands in the markdown rather than committing separate Docker files. The Scenarios section must be filled out by a human at all times. Follow `documentation/modules/module_doc_template.md` as a template
- If there's only one `ACTION` in the exploit, it can likely be omitted

#### Payloads and Targets

- When possible don't set a default payload (`DefaultOptions` with `'PAYLOAD'`) in modules — let the framework choose the most appropriate payload automatically
- Define bad characters instead of explicitly base-64 encoding payloads
- Don't check the number of sessions at the end of an exploit and report success based on that — not all payloads open sessions
- Don't submit any kind of opaque binary blob — everything must include source code and build instructions

**Payload selection guidance:**

| Scenario | Approach |
|----------|----------|
| Only command execution available (no file write) | Use `ARCH_CMD` payloads |
| Only HTTP(S) outbound (curl/wget available) | Use fetch payload (`Msf::Exploit::Remote::HttpServer` + fetch handler) |
| File write possible on target | Use dropper/EXE payload (`Msf::Exploit::EXE`) |
| Full command stager needed (multi-step upload) | Use `Msf::Exploit::CmdStager` — but prefer fetch when only download mechanisms are available |

#### File and Network Operations

- When overriding `cleanup`, always call `super` to ensure the parent mixin chain cleans up connections and sessions properly
- When opening a file, make sure the file exists first
- Don't print host information like `#{ip}:#{port}` because it doesn't handle IPv6 addresses — use `#{Rex::Socket.to_authority(ip, port)}`
- Use the TEST-NET-1 range for example / non-routeable IP addresses in unit tests and spec files: `192.0.2.0`. Local/private IPs are fine in module documentation scenarios

#### Output and Reporting

- All `print_*` calls should start with a capital letter
- Call `report_service` when a service can be reported
- Call `report_vuln` when a vulnerability can be reported
- When creating a fake account / username use the `Faker` gem (e.g. `Faker::Internet.username`) not `Rex::Text.rand_text_alphanumeric`

#### Session and Post-Exploitation

- Use `create_process(executable, args: [], time_out: 15, opts: {})` instead of the deprecated `cmd_exec` with separate arguments
- Use `Msf::OptionalSession` for modules that work both with and without an existing session (e.g. local exploits that can also run standalone)
- Use the module mixin APIs — don't reinvent the wheel

#### Internationalisation Considerations

- When checking for a string in a response — will it always be in English?
- Ensure hardcoded strings being regex'ed will be consistent across multiple versions

### Check Methods

- `check` methods must only return `CheckCode` values (e.g. `CheckCode::Vulnerable`, `CheckCode::Safe`) — never raise exceptions or call `fail_with`
- When writing a `check` method, verify it does not produce false positives when run against unrelated software or services
- Prefer using `Rex::Version` for version checks
- Use `fail_with(Failure::UnexpectedReply, '...')` (and other `Failure::*` constants) to bail out of `exploit`/`run` methods — don't use `raise` or bare `return` for error conditions
- `get_version` methods should return a REX version
- `CheckCode::Vulnerable` is only used when the vulnerability has been exploited
- `CheckCode::Appears` is only used when the application's version has been checked
- Always provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Safe("Target is running patched version #{version}")` — never return a bare constant or empty call
- Use specific regular expressions or `res.get_html_document` for version extraction with CSS selectors. Don't use generic selectors like `href .*` to grab the version — be more precise
- Catch exceptions that may be raised and ensure a valid CheckCode is returned
- Research and determine a minimum version where the application is vulnerable; mark prior versions as safe
- Check helper methods used by both `#check` and `#exploit` (or `#run`) — ensure there is no condition (exception, return, etc.) where `#check` could return something other than a CheckCode
- Prefer `prepend Msf::Exploit::Remote::AutoCheck` over manually calling `check` inside `exploit` — this lets the framework handle check-before-exploit automatically

### Library Code

When writing or modifying code in `lib/`:

#### Error Handling
- Use specific error classes (`Rex::RuntimeError`, `Rex::ConnectionError`, `ArgumentError`, `Rex::TimeoutError`) — never `raise "bare string"` which makes targeted rescue impossible
- Use `rescue StandardError => e` or a more specific class — never bare `rescue` (it discards the exception object, making debugging impossible) and never `rescue Exception` (it catches `SignalException` and `SystemExit`, hiding Ctrl-C and kill signals)
- Propagate errors with context: `raise Rex::ConnectionError, "Failed to connect to #{host}: #{e.message}"`

#### Documentation and Style
- Add YARD `@param` and `@return` tags to all public methods
- Add `# frozen_string_literal: true` to new library files
- Avoid `get_`/`set_` prefixes for accessor-style methods in new code (Ruby convention: use the attribute name directly, e.g. `def version` not `def get_version`)
- Link to the specification or RFC when implementing binary/protocol parsers

#### Quality
- Write RSpec tests for any library changes — tests live in `spec/` mirroring the `lib/` structure
- Follow [Better Specs](https://www.betterspecs.org/) conventions
- Keep PRs focused — small fixes are easier to review
- Any new hash cracking implementations require adding a test hash to `tools/dev/hash_cracker_validator.rb` and ensuring that passes without error

### Testing

- Tests live in `spec/` mirroring the `lib/` structure
- Run a single spec file: `bundle exec rspec spec/path/to/spec.rb`
- Run a single example by line: `bundle exec rspec spec/path/to/spec.rb:42`
- Run the full suite: `bundle exec rake spec` (slow — prefer targeted runs during development)
- Module functional tests live under `spec/modules/` and test end-to-end behaviour
- Always run specs relevant to your change before submitting

### Preferred Libraries

- Use the `RubySMB` library for SMB modules
- Use `Rex::Stopwatch.elapsed_time` to track elapsed time
- Use the `Rex::MIME::Message` class for MIME messages instead of hardcoding XML
- When creating random variable names prefer `Rex::RandomIdentifier::Generator` and specify the runtime language used. This avoids generating language keywords that would break the script
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

### Console Output

- Use `print_status`, `print_good`, `print_error`, `print_warning` for console output
- Use `vprint_*` variants for verbose-only output (shown when user sets `VERBOSE true`)

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

### Network Operations

- Use `send_request_cgi` for HTTP requests in modules
- Use `connect` / `disconnect` for TCP socket operations
- Use the `srvhost` method to access the server host — don't use `datastore['SRVHOST']` directly (enforced by `Lint/DatastoreSrvhostUsage` cop)

## Legacy Patterns (Migration Guidance)

These patterns exist in older code but should not be used in new modules or library code. When touching existing code that uses these patterns, prefer modernizing it:

| Legacy Pattern | Modern Replacement | Notes |
|---------------|-------------------|-------|
| `HttpFingerprint = { :pattern => [...] }` | Implement a `check` method + `prepend AutoCheck` | HttpFingerprint is a passive fingerprinting mechanism that predates the check API |
| `cmd_exec("command #{user_input}")` | `create_process("command", args: [user_input])` | String interpolation in cmd_exec is a command injection risk; create_process separates executable from arguments by design |
| `cmd_exec(cmd, args_string, timeout)` | `create_process(cmd, args: args_array, time_out: timeout)` | Enforced by `Lint/DetectOutdatedCmdExecApi` rubocop cop |
| `DefaultOptions => { 'PAYLOAD' => '...' }` | Remove — let the framework choose automatically | Only acceptable when the module genuinely only works with a single specific payload |
| `include Msf::Exploit::Remote::AutoCheck` | `prepend Msf::Exploit::Remote::AutoCheck` | Include raises NotImplementedError; prepend is required |
| Bare `rescue` in library code | `rescue StandardError => e` | Bare rescue discards the exception object; `rescue Exception` is worse — it catches signals/exits |
| `raise "error message"` in library code | `raise Rex::RuntimeError, "message"` | Specific classes enable targeted error handling |
| Manual `check` call inside `exploit` | `prepend AutoCheck` + separate `check` method | Let the framework handle check-before-exploit |

### Modernizing Existing Modules

When updating an existing module, the lowest-effort improvement is adding AutoCheck:

```ruby
# If the module already has a `def check` method, just add this line
# after the other includes:
prepend Msf::Exploit::Remote::AutoCheck
```

This single addition gives users the ability to verify vulnerability before exploitation, with automatic abort if the target is not vulnerable (overridable with `set ForceExploit true`).

## Before Submitting

- Work on a topic branch — don't commit directly to `master`
- Follow the [50/72 rule](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) for Git commit messages (50 char subject, 72 char body wrap)
- Ensure `rubocop` and `msftidy` pass on any changed files with no new offenses
- Ensure `ruby tools/dev/msftidy_docs.rb <documentation_file>` passes on any changed documentation markdown docs with no new offenses
- Include console output (especially `msfconsole` demonstrations) in your pull request when the changes have observable effects
- Include verification steps so reviewers can test your changes
- Reference associated issues in your pull request description (e.g., `See #1234`)

## What NOT to Do

- Don't submit untested code — all code must be manually verified
- Don't include sensitive information (IPs, credentials, API keys, hashes of credentials) in code or docs
- Don't include more than one module per pull request
- Don't add new scripts to `scripts/` — use post modules instead
- Don't use `pack`/`unpack` with invalid directives (enforced by linter)
