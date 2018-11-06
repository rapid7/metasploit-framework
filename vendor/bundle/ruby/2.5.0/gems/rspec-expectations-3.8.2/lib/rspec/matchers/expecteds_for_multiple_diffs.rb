module RSpec
  module Matchers
    # @api private
    # Handles list of expected values when there is a need to render
    # multiple diffs. Also can handle one value.
    class ExpectedsForMultipleDiffs
      # @private
      # Default diff label when there is only one matcher in diff
      # output
      DEFAULT_DIFF_LABEL = "Diff:".freeze

      # @private
      # Maximum readable matcher description length
      DESCRIPTION_MAX_LENGTH = 65

      def initialize(expected_list)
        @expected_list = expected_list
      end

      # @api private
      # Wraps provided expected value in instance of
      # ExpectedForMultipleDiffs. If provided value is already an
      # ExpectedForMultipleDiffs then it just returns it.
      # @param [Any] expected value to be wrapped
      # @return [RSpec::Matchers::ExpectedsForMultipleDiffs]
      def self.from(expected)
        return expected if self === expected
        new([[expected, DEFAULT_DIFF_LABEL]])
      end

      # @api private
      # Wraps provided matcher list in instance of
      # ExpectedForMultipleDiffs.
      # @param [Array<Any>] matchers list of matchers to wrap
      # @return [RSpec::Matchers::ExpectedsForMultipleDiffs]
      def self.for_many_matchers(matchers)
        new(matchers.map { |m| [m.expected, diff_label_for(m)] })
      end

      # @api private
      # Returns message with diff(s) appended for provided differ
      # factory and actual value if there are any
      # @param [String] message original failure message
      # @param [Proc] differ
      # @param [Any] actual value
      # @return [String]
      def message_with_diff(message, differ, actual)
        diff = diffs(differ, actual)
        message = "#{message}\n#{diff}" unless diff.empty?
        message
      end

    private

      def self.diff_label_for(matcher)
        "Diff for (#{truncated(RSpec::Support::ObjectFormatter.format(matcher))}):"
      end

      def self.truncated(description)
        return description if description.length <= DESCRIPTION_MAX_LENGTH
        description[0...DESCRIPTION_MAX_LENGTH - 3] << "..."
      end

      def diffs(differ, actual)
        @expected_list.map do |(expected, diff_label)|
          diff = differ.diff(actual, expected)
          next if diff.strip.empty?
          "#{diff_label}#{diff}"
        end.compact.join("\n")
      end
    end
  end
end
