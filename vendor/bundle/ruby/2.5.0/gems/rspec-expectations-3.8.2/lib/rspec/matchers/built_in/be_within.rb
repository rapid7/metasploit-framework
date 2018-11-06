module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `be_within`.
      # Not intended to be instantiated directly.
      class BeWithin < BaseMatcher
        def initialize(delta)
          @delta = delta
        end

        # @api public
        # Sets the expected value.
        def of(expected)
          @expected  = expected
          @tolerance = @delta
          @unit      = ''
          self
        end

        # @api public
        # Sets the expected value, and makes the matcher do
        # a percent comparison.
        def percent_of(expected)
          @expected  = expected
          @tolerance = @delta * @expected.abs / 100.0
          @unit      = '%'
          self
        end

        # @private
        def matches?(actual)
          @actual = actual
          raise needs_expected unless defined? @expected
          numeric? && (@actual - @expected).abs <= @tolerance
        end

        # @api private
        # @return [String]
        def failure_message
          "expected #{actual_formatted} to #{description}#{not_numeric_clause}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected #{actual_formatted} not to #{description}"
        end

        # @api private
        # @return [String]
        def description
          "be within #{@delta}#{@unit} of #{@expected}"
        end

      private

        def numeric?
          @actual.respond_to?(:-)
        end

        def needs_expected
          ArgumentError.new "You must set an expected value using #of: be_within(#{@delta}).of(expected_value)"
        end

        def not_numeric_clause
          ", but it could not be treated as a numeric value" unless numeric?
        end
      end
    end
  end
end
