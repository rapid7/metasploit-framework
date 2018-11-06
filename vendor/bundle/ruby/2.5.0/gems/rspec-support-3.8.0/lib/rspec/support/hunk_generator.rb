require 'diff/lcs'
require 'diff/lcs/hunk'

module RSpec
  module Support
    # @private
    class HunkGenerator
      def initialize(actual, expected)
        @actual = actual
        @expected = expected
      end

      def hunks
        @file_length_difference = 0
        @hunks ||= diffs.map do |piece|
          build_hunk(piece)
        end
      end

    private

      def diffs
        Diff::LCS.diff(expected_lines, actual_lines)
      end

      def expected_lines
        @expected.split("\n").map! { |e| e.chomp }
      end

      def actual_lines
        @actual.split("\n").map! { |e| e.chomp }
      end

      def build_hunk(piece)
        Diff::LCS::Hunk.new(
          expected_lines, actual_lines, piece, context_lines, @file_length_difference
        ).tap do |h|
          @file_length_difference = h.file_length_difference
        end
      end

      def context_lines
        3
      end
    end
  end
end
