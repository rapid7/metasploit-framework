module RSpec
  module Support
    # Provides a means to fuzzy-match between two arbitrary objects.
    # Understands array/hash nesting. Uses `===` or `==` to
    # perform the matching.
    module FuzzyMatcher
      # @api private
      def self.values_match?(expected, actual)
        if Hash === actual
          return hashes_match?(expected, actual) if Hash === expected
        elsif Array === expected && Enumerable === actual && !(Struct === actual)
          return arrays_match?(expected, actual.to_a)
        end

        return true if expected == actual

        begin
          expected === actual
        rescue ArgumentError
          # Some objects, like 0-arg lambdas on 1.9+, raise
          # ArgumentError for `expected === actual`.
          false
        end
      end

      # @private
      def self.arrays_match?(expected_list, actual_list)
        return false if expected_list.size != actual_list.size

        expected_list.zip(actual_list).all? do |expected, actual|
          values_match?(expected, actual)
        end
      end

      # @private
      def self.hashes_match?(expected_hash, actual_hash)
        return false if expected_hash.size != actual_hash.size

        expected_hash.all? do |expected_key, expected_value|
          actual_value = actual_hash.fetch(expected_key) { return false }
          values_match?(expected_value, actual_value)
        end
      end

      private_class_method :arrays_match?, :hashes_match?
    end
  end
end
