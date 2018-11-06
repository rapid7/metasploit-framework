# coding: utf-8

class PDF::Reader
  module WidthCalculator
    # Calculates the width of a glyph in a Type One or Type Three
    class TypeOneOrThree

      def initialize(font)
        @font = font

        if @font.font_descriptor
          @missing_width = @font.font_descriptor.missing_width
        else
          @missing_width = 0
        end
      end

      def glyph_width(code_point)
        return 0 if code_point.nil? || code_point < 0
        return 0 if @font.widths.nil? || @font.widths.count == 0

        # in ruby a negative index is valid, and will go from the end of the array
        # which is undesireable in this case.
        if @font.first_char <= code_point
          @font.widths.fetch(code_point - @font.first_char, @missing_width).to_f
        else
          @missing_width.to_f
        end
      end
    end
  end
end
