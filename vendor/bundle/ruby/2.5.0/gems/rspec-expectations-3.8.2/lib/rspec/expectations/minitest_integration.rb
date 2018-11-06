require 'rspec/expectations'

Minitest::Test.class_eval do
  include ::RSpec::Matchers

  # This `expect` will only be called if the user is using Minitest < 5.6
  # or if they are _not_ using Minitest::Spec on 5.6+. Minitest::Spec on 5.6+
  # defines its own `expect` and will have the assertions incremented via our
  # definitions of `to`/`not_to`/`to_not` below.
  def expect(*a, &b)
    self.assertions += 1
    super
  end

  # Convert a `MultipleExpectationsNotMetError` to a `Minitest::Assertion` error so
  # it gets counted in minitest's summary stats as a failure rather than an error.
  # It would be nice to make `MultipleExpectationsNotMetError` subclass
  # `Minitest::Assertion`, but Minitest's implementation does not treat subclasses
  # the same, so this is the best we can do.
  def aggregate_failures(*args, &block)
    super
  rescue RSpec::Expectations::MultipleExpectationsNotMetError => e
    assertion_failed = Minitest::Assertion.new(e.message)
    assertion_failed.set_backtrace e.backtrace
    raise assertion_failed
  end
end

# Older versions of Minitest (e.g. before 5.6) do not define
# `Minitest::Expectation`.
if defined?(::Minitest::Expectation)
  Minitest::Expectation.class_eval do
    include RSpec::Expectations::ExpectationTarget::InstanceMethods

    def to(*args)
      ctx.assertions += 1
      super
    end

    def not_to(*args)
      ctx.assertions += 1
      super
    end

    def to_not(*args)
      ctx.assertions += 1
      super
    end
  end
end

module RSpec
  module Expectations
    remove_const :ExpectationNotMetError
    # Exception raised when an expectation fails.
    const_set :ExpectationNotMetError, ::Minitest::Assertion
  end
end
