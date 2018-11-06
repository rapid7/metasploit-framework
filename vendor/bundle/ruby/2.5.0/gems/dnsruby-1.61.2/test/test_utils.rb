require_relative 'spec_helper'

# Use this in tests in the tests directory with:
# require_relative 'test_utils'
# include TestUtils

module Dnsruby
  module TestUtils

    module_function

    # Asserts that all exceptions whose type are the specified exception class
    # or one of its subclasses are *not* raised.
    #
    # If any other kind of exception is raised, the test throws an exception
    # (rather than failing).
    #
    # The test passes if and only if no exceptions are raised.
    def assert_not_raised(exception_class, failure_message = nil)
      begin
        yield
      rescue => e
        if e.is_a?(exception_class)
          flunk(failure_message || "An exception was not expected but was raised: #{e}")
        else
          raise e
        end
      end
    end

=begin
  # This should result in a test failure:
  def test_target_exception
    assert_not_raised(ArgumentError, 'ArgumentError') { raise ArgumentError.new }
  end

  # This should result in a test error:
  def test_other_exception
    assert_not_raised(ArgumentError, 'RuntimeError') { raise RuntimeError.new }
  end

  # This should result in a passed test:
  def test_no_exception
    assert_not_raised(ArgumentError, 'No Error') { }
  end
=end
  end
end

