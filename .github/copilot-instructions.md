# Metasploit Framework — Copilot Instructions

## Project Overview

Metasploit Framework is a Ruby penetration testing and exploitation framework. Modules (exploits, auxiliary, post, payloads, encoders, evasion) live in `modules/`. Core libraries live in `lib/msf/` and `lib/rex/`. Tests are in `spec/`.

## Tech Stack

- Ruby 3.1+ (see `.ruby-version`)
- RSpec for testing (`bundle exec rspec spec/path/to/spec.rb`)
- RuboCop for linting (custom cops in `lib/rubocop/cop/`)
- `tools/dev/msftidy.rb` for module-specific checks

## Key Coding Rules

- Add `# frozen_string_literal: true` to new files
- Use `%q{}` for multi-line module descriptions
- Don't use `get_`/`set_` prefixes for accessor methods
- All `print_*` calls start with a capital letter
- Use `Rex::Socket.to_authority(ip, port)` for host:port (IPv6 safe)
- Use `res.get_json_document` not `JSON.parse(res.body)`
- Use `fail_with(Failure::*, 'reason')` for error conditions in exploit/run methods
- Use `create_process(executable, args: [])` not `cmd_exec` with separate arguments

## Module Structure (Exploit)

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient    # 1. Protocol mixins
  include Msf::Exploit::FileDropper           # 2. Utility mixins
  prepend Msf::Exploit::Remote::AutoCheck     # 3. ALWAYS LAST — prepend not include

  def initialize(info = {})
    super(update_info(info, 'Name' => ..., 'Notes' => { 'Stability' => [CRASH_SAFE], 'SideEffects' => [IOC_IN_LOGS], 'Reliability' => [REPEATABLE_SESSION] }))
  end

  def check
    CheckCode::Safe('Reason string required')  # Never bare constants
  end

  def exploit; end
end
```

## Check Methods

- Must return `CheckCode` values only — never raise or call `fail_with`
- `CheckCode::Vulnerable` = vulnerability was exploited; `CheckCode::Appears` = version check
- Always include a reason string: `CheckCode::Safe("Patched version #{v}")`
- Use `Rex::Version` for version comparisons
- Prefer `prepend Msf::Exploit::Remote::AutoCheck` over manual check calls

## Library Code (`lib/`)

- Use specific error classes (`Rex::RuntimeError`, `Rex::ConnectionError`) — never `raise "string"`
- Use `rescue StandardError => e` — never bare `rescue`
- Add YARD `@param`/`@return` to public methods
- Write RSpec tests for all library changes

## Before Submitting

- Run `rubocop` and `msftidy` on changed files
- Run `ruby tools/dev/msftidy_docs.rb` on documentation files
- One module per PR; keep PRs focused
- Include verification steps and console output

## Full Reference

See [AGENTS.md](../AGENTS.md) for complete templates (auxiliary, post modules), payload selection guidance, Notes hash reference, legacy pattern migration table, and detailed subsection guidance.
