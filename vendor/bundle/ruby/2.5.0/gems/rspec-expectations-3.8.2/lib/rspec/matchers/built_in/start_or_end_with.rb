module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Base class for the `end_with` and `start_with` matchers.
      # Not intended to be instantiated directly.
      class StartOrEndWith < BaseMatcher
        def initialize(*expected)
          @actual_does_not_have_ordered_elements = false
          @expected = expected.length == 1 ? expected.first : expected
        end

        # @api private
        # @return [String]
        def failure_message
          super.tap do |msg|
            if @actual_does_not_have_ordered_elements
              msg << ", but it does not have ordered elements"
            elsif !actual.respond_to?(:[])
              msg << ", but it cannot be indexed using #[]"
            end
          end
        end

        # @api private
        # @return [String]
        def description
          return super unless Hash === expected
          english_name = EnglishPhrasing.split_words(self.class.matcher_name)
          description_of_expected = surface_descriptions_in(expected).inspect
          "#{english_name} #{description_of_expected}"
        end

      private

        def match(_expected, actual)
          return false unless actual.respond_to?(:[])

          begin
            return true if subsets_comparable? && subset_matches?
            element_matches?
          rescue ArgumentError
            @actual_does_not_have_ordered_elements = true
            return false
          end
        end

        def subsets_comparable?
          # Structs support the Enumerable interface but don't really have
          # the semantics of a subset of a larger set...
          return false if Struct === expected

          expected.respond_to?(:length)
        end
      end

      # For RSpec 3.1, the base class was named `StartAndEndWith`. For SemVer reasons,
      # we still provide this constant until 4.0.
      # @deprecated Use StartOrEndWith instead.
      # @private
      StartAndEndWith = StartOrEndWith

      # @api private
      # Provides the implementation for `start_with`.
      # Not intended to be instantiated directly.
      class StartWith < StartOrEndWith
      private

        def subset_matches?
          values_match?(expected, actual[0, expected.length])
        end

        def element_matches?
          values_match?(expected, actual[0])
        end
      end

      # @api private
      # Provides the implementation for `end_with`.
      # Not intended to be instantiated directly.
      class EndWith < StartOrEndWith
      private

        def subset_matches?
          values_match?(expected, actual[-expected.length, expected.length])
        end

        def element_matches?
          values_match?(expected, actual[-1])
        end
      end
    end
  end
end
