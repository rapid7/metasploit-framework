# RSpec Tests

RSpec tests live under this directory. Follow [Better Specs](https://www.betterspecs.org/)
when creating or updating tests throughout Framework, including library, module, and
acceptance specs. Every example must produce a meaningful, human-readable
description. RSpec-generated descriptions are acceptable when they clearly
describe the expected behavior; otherwise, provide an explicit description.

Keep examples focused and deterministic. Use `described_class`, `let`/`let!` for
setup, and `before` for side effects where appropriate. Prefer one expectation
per example when practical, and cover relevant valid, invalid, and boundary cases.

For library behavior changes, add or update focused specs under `spec/lib/`,
mirroring the library path. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the
project's test requirements.

Run a relevant spec file with `bundle exec rspec spec/path/to/spec.rb`, or a
single example with `bundle exec rspec spec/path/to/spec.rb:42`. See the
[acceptance test README](acceptance/README.md) for acceptance suite setup.
