module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `be_between`.
      # Not intended to be instantiated directly.
      class BeBetween < BaseMatcher
        def initialize(min, max)
          @min, @max = min, max
          inclusive
        end

        # @api public
        # Makes the between comparison inclusive.
        #
        # @example
        #   expect(3).to be_between(2, 3).inclusive
        #
        # @note The matcher is inclusive by default; this simply provides
        #       a way to be more explicit about it.
        def inclusive
          @less_than_operator = :<=
          @greater_than_operator = :>=
          @mode = :inclusive
          self
        end

        # @api public
        # Makes the between comparison exclusive.
        #
        # @example
        #   expect(3).to be_between(2, 4).exclusive
        def exclusive
          @less_than_operator = :<
          @greater_than_operator = :>
          @mode = :exclusive
          self
        end

        # @api private
        # @return [Boolean]
        def matches?(actual)
          @actual = actual
          comparable? && compare
        rescue ArgumentError
          false
        end

        # @api private
        # @return [String]
        def failure_message
          "#{super}#{not_comparable_clause}"
        end

        # @api private
        # @return [String]
        def description
          "be between #{description_of @min} and #{description_of @max} (#{@mode})"
        end

      private

        def comparable?
          @actual.respond_to?(@less_than_operator) && @actual.respond_to?(@greater_than_operator)
        end

        def not_comparable_clause
          ", but it does not respond to `#{@less_than_operator}` and `#{@greater_than_operator}`" unless comparable?
        end

        def compare
          @actual.__send__(@greater_than_operator, @min) && @actual.__send__(@less_than_operator, @max)
        end
      end
    end
  end
end
