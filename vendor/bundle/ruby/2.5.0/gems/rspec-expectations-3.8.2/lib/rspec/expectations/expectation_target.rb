module RSpec
  module Expectations
    # Wraps the target of an expectation.
    #
    # @example
    #   expect(something)       # => ExpectationTarget wrapping something
    #   expect { do_something } # => ExpectationTarget wrapping the block
    #
    #   # used with `to`
    #   expect(actual).to eq(3)
    #
    #   # with `not_to`
    #   expect(actual).not_to eq(3)
    #
    # @note `ExpectationTarget` is not intended to be instantiated
    #   directly by users. Use `expect` instead.
    class ExpectationTarget
      # @private
      # Used as a sentinel value to be able to tell when the user
      # did not pass an argument. We can't use `nil` for that because
      # `nil` is a valid value to pass.
      UndefinedValue = Module.new

      # @note this name aligns with `Minitest::Expectation` so that our
      #   {InstanceMethods} module can be included in that class when
      #   used in a Minitest context.
      # @return [Object] the target of the expectation
      attr_reader :target

      # @api private
      def initialize(value)
        @target = value
      end

      # @private
      def self.for(value, block)
        if UndefinedValue.equal?(value)
          unless block
            raise ArgumentError, "You must pass either an argument or a block to `expect`."
          end
          BlockExpectationTarget.new(block)
        elsif block
          raise ArgumentError, "You cannot pass both an argument and a block to `expect`."
        else
          new(value)
        end
      end

      # Defines instance {ExpectationTarget} instance methods. These are defined
      # in a module so we can include it in `Minitest::Expectation` when
      # `rspec/expectations/minitest_integration` is loaded in order to
      # support usage with Minitest.
      module InstanceMethods
        # Runs the given expectation, passing if `matcher` returns true.
        # @example
        #   expect(value).to eq(5)
        #   expect { perform }.to raise_error
        # @param [Matcher]
        #   matcher
        # @param [String or Proc] message optional message to display when the expectation fails
        # @return [Boolean] true if the expectation succeeds (else raises)
        # @see RSpec::Matchers
        def to(matcher=nil, message=nil, &block)
          prevent_operator_matchers(:to) unless matcher
          RSpec::Expectations::PositiveExpectationHandler.handle_matcher(target, matcher, message, &block)
        end

        # Runs the given expectation, passing if `matcher` returns false.
        # @example
        #   expect(value).not_to eq(5)
        # @param [Matcher]
        #   matcher
        # @param [String or Proc] message optional message to display when the expectation fails
        # @return [Boolean] false if the negative expectation succeeds (else raises)
        # @see RSpec::Matchers
        def not_to(matcher=nil, message=nil, &block)
          prevent_operator_matchers(:not_to) unless matcher
          RSpec::Expectations::NegativeExpectationHandler.handle_matcher(target, matcher, message, &block)
        end
        alias to_not not_to

      private

        def prevent_operator_matchers(verb)
          raise ArgumentError, "The expect syntax does not support operator matchers, " \
                               "so you must pass a matcher to `##{verb}`."
        end
      end

      include InstanceMethods
    end

    # @private
    # Validates the provided matcher to ensure it supports block
    # expectations, in order to avoid user confusion when they
    # use a block thinking the expectation will be on the return
    # value of the block rather than the block itself.
    class BlockExpectationTarget < ExpectationTarget
      def to(matcher, message=nil, &block)
        enforce_block_expectation(matcher)
        super
      end

      def not_to(matcher, message=nil, &block)
        enforce_block_expectation(matcher)
        super
      end
      alias to_not not_to

    private

      def enforce_block_expectation(matcher)
        return if supports_block_expectations?(matcher)

        raise ExpectationNotMetError, "You must pass an argument rather than a block to `expect` to use the provided " \
          "matcher (#{RSpec::Support::ObjectFormatter.format(matcher)}), or the matcher must implement " \
          "`supports_block_expectations?`."
      end

      def supports_block_expectations?(matcher)
        matcher.supports_block_expectations?
      rescue NoMethodError
        false
      end
    end
  end
end
