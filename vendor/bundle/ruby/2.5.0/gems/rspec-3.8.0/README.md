# RSpec

Behaviour Driven Development for Ruby

# Description

rspec is a meta-gem, which depends on the
[rspec-core](https://github.com/rspec/rspec-core),
[rspec-expectations](https://github.com/rspec/rspec-expectations)
and [rspec-mocks](https://github.com/rspec/rspec-mocks) gems. Each of these
can be installed separately and loaded in isolation using `require`. Among
other benefits, this allows you to use rspec-expectations, for example, in
Test::Unit::TestCase if you happen to prefer that style.

Conversely, if you like RSpec's approach to declaring example groups and
examples (`describe` and `it`) but prefer Test::Unit assertions and
[mocha](https://github.com/freerange/mocha), [rr](https://github.com/rr/rr)
or [flexmock](https://github.com/jimweirich/flexmock) for mocking, you'll be
able to do that without having to install or load the components of RSpec that
you're not using.

## Documentation

See http://rspec.info/documentation/ for links to documentation for all gems.

## Install

    gem install rspec

## Setup

    rspec --init

## Contribute

* [http://github.com/rspec/rspec-dev](http://github.com/rspec/rspec-dev)

## Also see

* [https://github.com/rspec/rspec-core](https://github.com/rspec/rspec-core)
* [https://github.com/rspec/rspec-expectations](https://github.com/rspec/rspec-expectations)
* [https://github.com/rspec/rspec-mocks](https://github.com/rspec/rspec-mocks)
* [https://github.com/rspec/rspec-rails](https://github.com/rspec/rspec-rails)
