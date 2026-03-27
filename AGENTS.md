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

## Coding Conventions

- Ruby (see `.ruby-version` for the current version). Minimum supported: 3.1+
- Follow the project's `.rubocop.yml` configuration — run `rubocop` on changed files before submitting
- Run `ruby tools/dev/msftidy.rb <module_file_path>` to catch common module issues
- Add `# frozen_string_literal: true` to new files (the RuboCop cop is disabled project-wide for legacy code, but new files should include it)
- No enforced line length limit, but keep code readable
- Use `%q{}` for long multi-line strings (curly braces preferred for module descriptions)
- Multiline block comments are acceptable for embedded code snippets/payloads
- Don't use `get_`/`set_` prefixes for accessor methods in new code
- Method parameter names must be at least 2 characters (exception for well-known crypto abbreviations)

### Module Development

- Prefer writing modules in Ruby. Go and Python modules are accepted, but their external runtimes don't support the full framework API (e.g. network pivoting). Ruby modules do not have this limitation
- Prefer using hash over an array for return values, and use kwargs for reusable APIs for future extensions
- Before writing a new module, check that there is not an existing module or open pull request that already covers the same functionality
- Each module should be in its own file under the appropriate `modules/` subdirectory. In some scenarios adding module actions or targets is preferred.
- Exploits require a `DisclosureDate` field
- Exploits, auxiliary, and post modules require `Notes` with `SideEffects`
- Use the module mixin APIs — don't reinvent the wheel
- Use `create_process(executable, args: [], time_out: 15, opts: {})` instead of the deprecated `cmd_exec` with separate arguments
- License new code with `MSF_LICENSE` (the project default, defined in `lib/msf/core/constants.rb`)
- When overriding `cleanup`, always call `super` to ensure the parent mixin chain cleans up connections and sessions properly
- When possible don't set a default payload (`DefaultOptions` with `'PAYLOAD'`) in modules — let the framework choose the most appropriate payload automatically
- New modules require an associated markdown file in the `documentation/modules` folder with the same structure, including steps to set up the vulnerable environment for testing
- Module descriptions or documentation should list the range of vulnerable versions and the fixed version of the affected software, when known
- `report_service` method called when a service can be reported
- `report_vuln` method called when a vuln can be reported
- When creating a fake account / username use FAKER not `rand_test_alphanumeric`
- Always use `res.get_json_document` to convert an HTTP response to a hash instead of calling `JSON.parse(res.body)`
- If there's only one `ACTION` in the exploit, it can likely be omitted.
- `Msf::Exploit::SQLi` should be used if it's exploiting an SQLi
- All `print_*` calls should start with a capital
- when opening a file, make sure the file exists first
- when checking for a string in a response - will it always be in english?
- Ensure hardcoded strings being regex'ed will be consistent across multiple versions
- Use the TEST-NET-1 range for example / non-routeable IP address: `192.0.2.0`
- Use fetch payload instead of command stagers when only options that request the stage are available (i.e. don’t use a cmd stager and only allow curl/wget).
- Define bad characters instead of explicitly base-64 encoding payloads
- Use `ARCH_CMD` payloads instead of command stagers when only curl/wget and other download mechanisms would be available
- Don’t check the number of sessions at the end of an exploit and report success based on that, not all payloads open sessions
- Don’t submit any kind of opaque binary blob, everything must include source code and build instructions
- Don’t print host information like `#{ip}:#{port}` because it doesn’t handle IPv6 addresses, instead use `#{Rex::Socket.to_authority(ip, port)}`
- Implement a `check` method when possible to allow users to verify vulnerability before exploitation

### Check Methods

- `check` methods must only return `CheckCode` values (e.g. `CheckCode::Vulnerable`, `CheckCode::Safe`) — never raise exceptions or call `fail_with`
- When writing a `check` method, verify it does not produce false positives when run against unrelated software or services
- Prefer using `Rex::Version` for version checks
- Use `fail_with(Failure::UnexpectedReply, '...')` (and other `Failure::*` constants) to bail out of `exploit`/`run` methods — don't use `raise` or bare `return` for error conditions
- `get_version` methods should return a REX version
- `CheckCode::Vulnerable` is only used when the vulnerability has been exploited
- `CheckCode::Appears`  is only used when the application's versions has been checked`
- Use specific regular expressions or `res.get_html_document` for version extraction with CSS selectors. Don't use a generic selectors like `href .*` dot star to grab the version, be more precise.
- Do catch exceptions that may be raised and ensure a valid Check Code is returned
- Do research and determine a minimum version where the application is vulnerable, mark prior versions as safe
- Check helper methods that are used by both `#check` and `#exploit` (or `#run`) and make sure there is no condition (exception, return, etc) where `#check` could return something else than CheckCode.
- Prefer `prepend Msf::Exploit::Remote::AutoCheck` over manually calling `check` inside `exploit` — this lets the framework handle check-before-exploit automatically

### Library Code

- When adding complex binary or protocol parsing (e.g. BinData, RASN1, Rex::Struct2), include a code comment linking to the specification or RFC that defines the format being implemented
- Write RSpec tests for any library changes
- Follow [Better Specs](http://www.betterspecs.org/) conventions
- Write YARD documentation for public methods
- Keep PRs focused — small fixes are easier to review
- Any new hash cracking implementations require adding a test hash to `tools/dev/hash_cracker_validator.rb` and ensuring that passes without error

### Testing

- Tests live in `spec/` mirroring the `lib/` structure
- Run tests with: `bundle exec rspec spec/path/to/spec.rb`

### Preferred Libraries

- Use the `RubySMB` library for SMB modules
- Use `Rex::Stopwatch.elapsed_time` to track elapsed time
- Use the `Rex::MIME::Message` class for MIME messages instead of hardcoding XML
- When creating random variable names prefer `Rex::RandomIdentifier::Generator` and specify the runtime language used. This avoids generating langauge keywords that would break the script.

## Common Patterns

- Register options with `register_options` and `register_advanced_options`
- Use `SCREAMING_SNAKE_CASE` option names and `CamelCase` advanced option names
- Use `datastore['OPTION_NAME']` to access module options
- Use `print_status`, `print_good`, `print_error`, `print_warning` for console output
- Use `vprint_*` variants for verbose-only output
- Use `send_request_cgi` for HTTP requests in modules
- Use `connect` / `disconnect` for TCP socket operations

## Before Submitting

- Ensure `rubocop` and `msftidy` pass on any changed files with no new offenses
- Ensure `ruby tools/dev/msftidy_docs.rb <documentation_file>` passes on any changed documentation markdown docs with no new offenses

## What NOT to Do

- Don't submit untested code — all code must be manually verified
- Don't include sensitive information (IPs, credentials, API keys, hashes of credentials) in code or docs
- Don't include more than one module per pull request
- Don't add new scripts to `scripts/` — use post modules instead
- Don't use `pack`/`unpack` with invalid directives (enforced by linter)
