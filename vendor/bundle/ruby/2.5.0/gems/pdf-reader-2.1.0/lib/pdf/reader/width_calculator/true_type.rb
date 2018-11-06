# coding: utf-8

class PDF::Reader
  module WidthCalculator
    # Calculates the width of a glyph in a TrueType font
    class TrueType

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

        glyph_width_from_font(code_point) || glyph_width_from_descriptor(code_point)
      end

      private

      #TODO convert Type3 units 1000 units => 1 text space unit
      def glyph_width_from_font(code_point)
        return if @font.widths.nil? || @font.widths.count == 0

        # in ruby a negative index is valid, and will go from the end of the array
        # which is undesireable in this case.
        if @font.first_char <= code_point
          @font.widths.fetch(code_point - @font.first_char, @missing_width).to_f
        else
          @missing_width.to_f
        end
      end

      def glyph_width_from_descriptor(code_point)
        return unless @font.font_descriptor

        # true type fonts will have most of their information contained
        # with-in a program inside the font descriptor, however the widths
        # may not be in standard PDF glyph widths (1000 units => 1 text space unit)
        # so this width will need to be scaled
        w = @font.font_descriptor.glyph_width(code_point)
        if w
          w.to_f * @font.font_descriptor.glyph_to_pdf_scale_factor
        else
          nil
        end
      end
    end
  end
end

