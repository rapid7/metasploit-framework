---
applyTo: "lib/**/*.rb"
---

# Library Code Instructions

## Error Handling

- Use specific error classes: `Rex::RuntimeError`, `Rex::ConnectionError`, `Rex::TimeoutError`, `ArgumentError`
- NEVER `raise "bare string"` — makes targeted rescue impossible
- NEVER bare `rescue` — it discards the exception object, making debugging impossible
- NEVER `rescue Exception` — it catches `SignalException` and `SystemExit` (hides Ctrl-C and kill signals)
- Always: `rescue StandardError => e` or more specific
- Propagate with context: `raise Rex::ConnectionError, "Failed to connect to #{host}: #{e.message}"`

## Documentation

- Add YARD `@param` and `@return` tags to ALL public methods
- Link to RFC/spec when implementing binary or protocol parsers
- Add `# frozen_string_literal: true` to new library files; use `String.new` where a mutable string is needed

## Naming

- Do NOT use `get_`/`set_` prefixes for accessor-style methods (use `def version` not `def get_version`)
- Method parameter names must be at least 2 characters

## Patterns

- Use `Rex::Stopwatch.elapsed_time` for timing
- Use `Rex::MIME::Message` for MIME (not hardcoded XML)
- Use `Rex::RandomIdentifier::Generator` for random variable names (specify target language)
- Use `RubySMB` library for SMB operations

## Testing

- ALL library changes require RSpec tests in `spec/` mirroring `lib/` structure
- Follow [Better Specs](https://www.betterspecs.org/) conventions
- Run: `bundle exec rspec spec/path/to/spec.rb` or `:42` for single example

## Quality

- Keep PRs focused — small fixes are easier to review
- When overriding `cleanup`, always call `super`
- Hash cracking implementations require test hash in `tools/dev/hash_cracker_validator.rb`
