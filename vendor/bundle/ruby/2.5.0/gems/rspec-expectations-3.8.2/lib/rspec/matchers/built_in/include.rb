module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `include`.
      # Not intended to be instantiated directly.
      class Include < BaseMatcher
        # @private
        attr_reader :expecteds

        def initialize(*expecteds)
          @expecteds = expecteds
        end

        # @api private
        # @return [Boolean]
        def matches?(actual)
          actual = actual.to_hash if convert_to_hash?(actual)
          perform_match(actual) { |v| v }
        end

        # @api private
        # @return [Boolean]
        def does_not_match?(actual)
          actual = actual.to_hash if convert_to_hash?(actual)
          perform_match(actual) { |v| !v }
        end

        # @api private
        # @return [String]
        def description
          improve_hash_formatting("include#{readable_list_of(expecteds)}")
        end

        # @api private
        # @return [String]
        def failure_message
          format_failure_message("to") { super }
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          format_failure_message("not to") { super }
        end

        # @api private
        # @return [Boolean]
        def diffable?
          !diff_would_wrongly_highlight_matched_item?
        end

        # @api private
        # @return [Array, Hash]
        def expected
          if expecteds.one? && Hash === expecteds.first
            expecteds.first
          else
            expecteds
          end
        end

      private

        def format_failure_message(preposition)
          if actual.respond_to?(:include?)
            improve_hash_formatting("expected #{description_of @actual} #{preposition} include#{readable_list_of @divergent_items}")
          else
            improve_hash_formatting(yield) + ", but it does not respond to `include?`"
          end
        end

        def readable_list_of(items)
          described_items = surface_descriptions_in(items)
          if described_items.all? { |item| item.is_a?(Hash) }
            " #{described_items.inject(:merge).inspect}"
          else
            EnglishPhrasing.list(described_items)
          end
        end

        def perform_match(actual, &block)
          @actual = actual
          @divergent_items = excluded_from_actual(&block)
          actual.respond_to?(:include?) && @divergent_items.empty?
        end

        def excluded_from_actual
          return [] unless @actual.respond_to?(:include?)

          expecteds.inject([]) do |memo, expected_item|
            if comparing_hash_to_a_subset?(expected_item)
              expected_item.each do |(key, value)|
                memo << { key => value } unless yield actual_hash_includes?(key, value)
              end
            elsif comparing_hash_keys?(expected_item)
              memo << expected_item unless yield actual_hash_has_key?(expected_item)
            else
              memo << expected_item unless yield actual_collection_includes?(expected_item)
            end
            memo
          end
        end

        def comparing_hash_to_a_subset?(expected_item)
          actual.is_a?(Hash) && expected_item.is_a?(Hash)
        end

        def actual_hash_includes?(expected_key, expected_value)
          actual_value = actual.fetch(expected_key) { return false }
          values_match?(expected_value, actual_value)
        end

        def comparing_hash_keys?(expected_item)
          actual.is_a?(Hash) && !expected_item.is_a?(Hash)
        end

        def actual_hash_has_key?(expected_key)
          # We check `key?` first for perf:
          # `key?` is O(1), but `any?` is O(N).
          actual.key?(expected_key) ||
          actual.keys.any? { |key| values_match?(expected_key, key) }
        end

        def actual_collection_includes?(expected_item)
          return true if actual.include?(expected_item)

          # String lacks an `any?` method...
          return false unless actual.respond_to?(:any?)

          actual.any? { |value| values_match?(expected_item, value) }
        end

        def diff_would_wrongly_highlight_matched_item?
          return false unless actual.is_a?(String) && expected.is_a?(Array)

          lines = actual.split("\n")
          expected.any? do |str|
            actual.include?(str) && lines.none? { |line| line == str }
          end
        end

        def convert_to_hash?(obj)
          !obj.respond_to?(:include?) && obj.respond_to?(:to_hash)
        end
      end
    end
  end
end
