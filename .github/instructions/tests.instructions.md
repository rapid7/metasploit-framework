---
applyTo: "spec/**/*_spec.rb"
---

# RSpec Test Instructions

## Conventions

- Follow [Better Specs](https://www.betterspecs.org/)
- Mirror `lib/` structure: `lib/msf/core/exploit/remote/http_client.rb` → `spec/lib/msf/core/exploit/remote/http_client_spec.rb`
- Use `described_class` instead of repeating the class name
- One expectation per example when practical
- Use `let` and `let!` for setup, `before` for side effects

## Running Tests

- Single file: `bundle exec rspec spec/path/to/spec.rb`
- Single example: `bundle exec rspec spec/path/to/spec.rb:42`
- Full suite: `bundle exec rake spec` (slow — avoid during development)

## Test Data

- Use TEST-NET-1 (`192.0.2.0/24`) for example IP addresses — never real IPs
- Use `Rex::Text.rand_text_alphanumeric` for random test data
- Use the `Faker` gem (e.g. `Faker::Internet.username`) for usernames/accounts

## Module Specs

- Module functional tests live in `spec/modules/`
- Test end-to-end behaviour including `check` and `exploit`/`run` methods

## What to Test

- Public API methods — inputs, outputs, edge cases
- Error handling paths — verify correct exception classes raised
- Protocol parsing — round-trip encode/decode
- Version comparison logic — boundary conditions
