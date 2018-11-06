# coding: utf-8

class PDF::Reader
  module WidthCalculator
    # Type0 (or Composite) fonts are a "root font" that rely on a "descendant font"
    # to do the heavy lifting. The "descendant font" is a CID-Keyed font.
    # see Section 9.7.1, PDF 32000-1:2008, pp 267
    # so if we are calculating a Type0 font width, we just pass off to
    # the descendant font
    class TypeZero

      def initialize(font)
        @font = font
        @descendant_font = @font.descendantfonts.first
      end

      def glyph_width(code_point)
        return 0 if code_point.nil? || code_point < 0

        @descendant_font.glyph_width(code_point).to_f
      end
    end
  end
end
