module RSpec
  module Matchers
    module BuiltIn
      # rubocop:disable ClassLength
      # @api private
      # Provides the implementation for `contain_exactly` and `match_array`.
      # Not intended to be instantiated directly.
      class ContainExactly < BaseMatcher
        # @api private
        # @return [String]
        def failure_message
          if Array === actual
            generate_failure_message
          else
            "expected a collection that can be converted to an array with " \
            "`#to_ary` or `#to_a`, but got #{actual_formatted}"
          end
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          list = EnglishPhrasing.list(surface_descriptions_in(expected))
          "expected #{actual_formatted} not to contain exactly#{list}"
        end

        # @api private
        # @return [String]
        def description
          list = EnglishPhrasing.list(surface_descriptions_in(expected))
          "contain exactly#{list}"
        end

      private

        def generate_failure_message
          message = expected_collection_line
          message += actual_collection_line
          message += missing_elements_line unless missing_items.empty?
          message += extra_elements_line unless extra_items.empty?
          message
        end

        def expected_collection_line
          message_line('expected collection contained', expected, true)
        end

        def actual_collection_line
          message_line('actual collection contained', actual)
        end

        def missing_elements_line
          message_line('the missing elements were', missing_items, true)
        end

        def extra_elements_line
          message_line('the extra elements were', extra_items)
        end

        def describe_collection(collection, surface_descriptions=false)
          if surface_descriptions
            "#{description_of(safe_sort(surface_descriptions_in collection))}\n"
          else
            "#{description_of(safe_sort(collection))}\n"
          end
        end

        def message_line(prefix, collection, surface_descriptions=false)
          "%-32s%s" % [prefix + ':',
                       describe_collection(collection, surface_descriptions)]
        end

        def match(_expected, _actual)
          return false unless convert_actual_to_an_array
          match_when_sorted? || (extra_items.empty? && missing_items.empty?)
        end

        # This cannot always work (e.g. when dealing with unsortable items,
        # or matchers as expected items), but it's practically free compared to
        # the slowness of the full matching algorithm, and in common cases this
        # works, so it's worth a try.
        def match_when_sorted?
          values_match?(safe_sort(expected), safe_sort(actual))
        end

        def convert_actual_to_an_array
          if actual.respond_to?(:to_ary)
            @actual = actual.to_ary
          elsif actual.respond_to?(:to_a) && !to_a_disallowed?(actual)
            @actual = actual.to_a
          else
            false
          end
        end

        def safe_sort(array)
          array.sort
        rescue Support::AllExceptionsExceptOnesWeMustNotRescue
          array
        end

        if RUBY_VERSION == "1.8.7"
          def to_a_disallowed?(object)
            case object
            when NilClass, String then true
            else Kernel == RSpec::Support.method_handle_for(object, :to_a).owner
            end
          end
        else
          def to_a_disallowed?(object)
            NilClass === object
          end
        end

        def missing_items
          @missing_items ||= best_solution.unmatched_expected_indexes.map do |index|
            expected[index]
          end
        end

        def extra_items
          @extra_items ||= best_solution.unmatched_actual_indexes.map do |index|
            actual[index]
          end
        end

        def best_solution
          @best_solution ||= pairings_maximizer.find_best_solution
        end

        def pairings_maximizer
          @pairings_maximizer ||= begin
            expected_matches = Hash[Array.new(expected.size) { |i| [i, []] }]
            actual_matches   = Hash[Array.new(actual.size)   { |i| [i, []] }]

            expected.each_with_index do |e, ei|
              actual.each_with_index do |a, ai|
                next unless values_match?(e, a)

                expected_matches[ei] << ai
                actual_matches[ai] << ei
              end
            end

            PairingsMaximizer.new(expected_matches, actual_matches)
          end
        end

        # Once we started supporting composing matchers, the algorithm for this matcher got
        # much more complicated. Consider this expression:
        #
        #   expect(["fool", "food"]).to contain_exactly(/foo/, /fool/)
        #
        # This should pass (because we can pair /fool/ with "fool" and /foo/ with "food"), but
        # the original algorithm used by this matcher would pair the first elements it could
        # (/foo/ with "fool"), which would leave /fool/ and "food" unmatched.  When we have
        # an expected element which is a matcher that matches a superset of actual items
        # compared to another expected element matcher, we need to consider every possible pairing.
        #
        # This class is designed to maximize the number of actual/expected pairings -- or,
        # conversely, to minimize the number of unpaired items. It's essentially a brute
        # force solution, but with a few heuristics applied to reduce the size of the
        # problem space:
        #
        #   * Any items which match none of the items in the other list are immediately
        #     placed into the `unmatched_expected_indexes` or `unmatched_actual_indexes` array.
        #     The extra items and missing items in the matcher failure message are derived
        #     from these arrays.
        #   * Any items which reciprocally match only each other are paired up and not
        #     considered further.
        #
        # What's left is only the items which match multiple items from the other list
        # (or vice versa). From here, it performs a brute-force depth-first search,
        # looking for a solution which pairs all elements in both lists, or, barring that,
        # that produces the fewest unmatched items.
        #
        # @private
        class PairingsMaximizer
          # @private
          Solution = Struct.new(:unmatched_expected_indexes,     :unmatched_actual_indexes,
                                :indeterminate_expected_indexes, :indeterminate_actual_indexes) do
            def worse_than?(other)
              unmatched_item_count > other.unmatched_item_count
            end

            def candidate?
              indeterminate_expected_indexes.empty? &&
              indeterminate_actual_indexes.empty?
            end

            def ideal?
              candidate? && (
                unmatched_expected_indexes.empty? ||
                unmatched_actual_indexes.empty?
              )
            end

            def unmatched_item_count
              unmatched_expected_indexes.count + unmatched_actual_indexes.count
            end

            def +(derived_candidate_solution)
              self.class.new(
                unmatched_expected_indexes + derived_candidate_solution.unmatched_expected_indexes,
                unmatched_actual_indexes   + derived_candidate_solution.unmatched_actual_indexes,
                # Ignore the indeterminate indexes: by the time we get here,
                # we've dealt with all indeterminates.
                [], []
              )
            end
          end

          attr_reader :expected_to_actual_matched_indexes, :actual_to_expected_matched_indexes, :solution

          def initialize(expected_to_actual_matched_indexes, actual_to_expected_matched_indexes)
            @expected_to_actual_matched_indexes = expected_to_actual_matched_indexes
            @actual_to_expected_matched_indexes = actual_to_expected_matched_indexes

            unmatched_expected_indexes, indeterminate_expected_indexes =
              categorize_indexes(expected_to_actual_matched_indexes, actual_to_expected_matched_indexes)

            unmatched_actual_indexes, indeterminate_actual_indexes =
              categorize_indexes(actual_to_expected_matched_indexes, expected_to_actual_matched_indexes)

            @solution = Solution.new(unmatched_expected_indexes,     unmatched_actual_indexes,
                                     indeterminate_expected_indexes, indeterminate_actual_indexes)
          end

          def find_best_solution
            return solution if solution.candidate?
            best_solution_so_far = NullSolution

            expected_index = solution.indeterminate_expected_indexes.first
            actuals = expected_to_actual_matched_indexes[expected_index]

            actuals.each do |actual_index|
              solution = best_solution_for_pairing(expected_index, actual_index)
              return solution if solution.ideal?
              best_solution_so_far = solution if best_solution_so_far.worse_than?(solution)
            end

            best_solution_so_far
          end

        private

          # @private
          # Starting solution that is worse than any other real solution.
          NullSolution = Class.new do
            def self.worse_than?(_other)
              true
            end
          end

          def categorize_indexes(indexes_to_categorize, other_indexes)
            unmatched     = []
            indeterminate = []

            indexes_to_categorize.each_pair do |index, matches|
              if matches.empty?
                unmatched << index
              elsif !reciprocal_single_match?(matches, index, other_indexes)
                indeterminate << index
              end
            end

            return unmatched, indeterminate
          end

          def reciprocal_single_match?(matches, index, other_list)
            return false unless matches.one?
            other_list[matches.first] == [index]
          end

          def best_solution_for_pairing(expected_index, actual_index)
            modified_expecteds = apply_pairing_to(
              solution.indeterminate_expected_indexes,
              expected_to_actual_matched_indexes, actual_index)

            modified_expecteds.delete(expected_index)

            modified_actuals = apply_pairing_to(
              solution.indeterminate_actual_indexes,
              actual_to_expected_matched_indexes, expected_index)

            modified_actuals.delete(actual_index)

            solution + self.class.new(modified_expecteds, modified_actuals).find_best_solution
          end

          def apply_pairing_to(indeterminates, original_matches, other_list_index)
            indeterminates.inject({}) do |accum, index|
              accum[index] = original_matches[index] - [other_list_index]
              accum
            end
          end
        end
      end
      # rubocop:enable ClassLength
    end
  end
end
