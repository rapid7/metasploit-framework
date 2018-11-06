class Pry
  class Code

    # Represents a range of lines in a code listing.
    #
    # @api private
    class CodeRange

      # @param [Integer] start_line
      # @param [Integer?] end_line
      def initialize(start_line, end_line = nil)
        @start_line = start_line
        @end_line   = end_line
        force_set_end_line
      end

      # @param [Array<LOC>] lines
      # @return [Range]
      def indices_range(lines)
        Range.new(*indices(lines))
      end

      private

      def start_line; @start_line; end
      def end_line; @end_line; end

      # If `end_line` is equal to `nil`, then calculate it from the first
      # parameter, `start_line`. Otherwise, leave it as it is.
      # @return [void]
      def force_set_end_line
        if start_line.is_a?(Range)
          set_end_line_from_range
        else
          @end_line ||= start_line
        end
      end

      # Finds indices of `start_line` and `end_line` in the given Array of
      # +lines+.
      #
      # @param [Array<LOC>] lines
      # @return [Array<Integer>]
      def indices(lines)
        [find_start_index(lines), find_end_index(lines)]
      end

      # @return [Integer]
      def find_start_index(lines)
        return start_line if start_line < 0
        lines.index { |loc| loc.lineno >= start_line } || lines.length
      end

      # @return [Integer]
      def find_end_index(lines)
        return end_line if end_line < 0
        (lines.index { |loc| loc.lineno > end_line } || 0) - 1
      end

      # For example, if the range is 4..10, then `start_line` would be equal to
      # 4 and `end_line` to 10.
      # @return [void]
      def set_end_line_from_range
        @end_line = start_line.last
        @end_line -= 1 if start_line.exclude_end?
        @start_line = start_line.first
      end
    end

  end
end
