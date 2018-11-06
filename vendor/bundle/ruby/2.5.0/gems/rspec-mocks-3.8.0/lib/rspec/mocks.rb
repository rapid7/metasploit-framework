require 'rspec/support'
RSpec::Support.require_rspec_support 'caller_filter'
RSpec::Support.require_rspec_support 'warnings'
RSpec::Support.require_rspec_support 'ruby_features'

RSpec::Support.define_optimized_require_for_rspec(:mocks) { |f| require_relative f }

%w[
  instance_method_stasher
  method_double
  argument_matchers
  example_methods
  proxy
  test_double
  argument_list_matcher
  message_expectation
  order_group
  error_generator
  space
  mutate_const
  targets
  syntax
  configuration
  verifying_double
  version
].each { |name| RSpec::Support.require_rspec_mocks name }

# Share the top-level RSpec namespace, because we are a core supported
# extension.
module RSpec
  # Contains top-level utility methods. While this contains a few
  # public methods, these are not generally meant to be called from
  # a test or example. They exist primarily for integration with
  # test frameworks (such as rspec-core).
  module Mocks
    # Performs per-test/example setup. This should be called before
    # an test or example begins.
    def self.setup
      @space_stack << (@space = space.new_scope)
    end

    # Verifies any message expectations that were set during the
    # test or example. This should be called at the end of an example.
    def self.verify
      space.verify_all
    end

    # Cleans up all test double state (including any methods that were
    # redefined on partial doubles). This _must_ be called after
    # each example, even if an error was raised during the example.
    def self.teardown
      space.reset_all
      @space_stack.pop
      @space = @space_stack.last || @root_space
    end

    # Adds an allowance (stub) on `subject`
    #
    # @param subject the subject to which the message will be added
    # @param message a symbol, representing the message that will be
    #                added.
    # @param opts a hash of options, :expected_from is used to set the
    #             original call site
    # @yield an optional implementation for the allowance
    #
    # @example Defines the implementation of `foo` on `bar`, using the passed block
    #   x = 0
    #   RSpec::Mocks.allow_message(bar, :foo) { x += 1 }
    def self.allow_message(subject, message, opts={}, &block)
      space.proxy_for(subject).add_stub(message, opts, &block)
    end

    # Sets a message expectation on `subject`.
    # @param subject the subject on which the message will be expected
    # @param message a symbol, representing the message that will be
    #                expected.
    # @param opts a hash of options, :expected_from is used to set the
    #             original call site
    # @yield an optional implementation for the expectation
    #
    # @example Expect the message `foo` to receive `bar`, then call it
    #   RSpec::Mocks.expect_message(bar, :foo)
    #   bar.foo
    def self.expect_message(subject, message, opts={}, &block)
      space.proxy_for(subject).add_message_expectation(message, opts, &block)
    end

    # Call the passed block and verify mocks after it has executed. This allows
    # mock usage in arbitrary places, such as a `before(:all)` hook.
    def self.with_temporary_scope
      setup

      begin
        yield
        verify
      ensure
        teardown
      end
    end

    class << self
      # @private
      attr_reader :space
    end
    @space_stack = []
    @root_space  = @space = RSpec::Mocks::RootSpace.new

    # @private
    IGNORED_BACKTRACE_LINE = 'this backtrace line is ignored'

    # To speed up boot time a bit, delay loading optional or rarely
    # used features until their first use.
    autoload :AnyInstance,      "rspec/mocks/any_instance"
    autoload :ExpectChain,      "rspec/mocks/message_chain"
    autoload :StubChain,        "rspec/mocks/message_chain"
    autoload :MarshalExtension, "rspec/mocks/marshal_extension"

    # Namespace for mock-related matchers.
    module Matchers
      # @private
      # just a "tag" for rspec-mock matchers detection
      module Matcher; end

      autoload :HaveReceived,        "rspec/mocks/matchers/have_received"
      autoload :Receive,             "rspec/mocks/matchers/receive"
      autoload :ReceiveMessageChain, "rspec/mocks/matchers/receive_message_chain"
      autoload :ReceiveMessages,     "rspec/mocks/matchers/receive_messages"
    end
  end
end
