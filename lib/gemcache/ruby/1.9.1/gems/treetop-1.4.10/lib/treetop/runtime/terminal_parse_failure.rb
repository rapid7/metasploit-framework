module Treetop
  module Runtime
    class TerminalParseFailure
      attr_reader :index, :expected_string

      def initialize(index, expected_string)
        @index = index
        @expected_string = expected_string
      end

      def to_s
        "String matching #{expected_string} expected."
      end
    end
  end
end
