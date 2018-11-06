require_relative '../../reader'

module TTFunk
  class Table
    class Glyf
      class Simple
        attr_reader :raw
        attr_reader :number_of_contours
        attr_reader :x_min, :y_min, :x_max, :y_max

        def initialize(raw, number_of_contours, x_min, y_min, x_max, y_max)
          @raw = raw
          @number_of_contours = number_of_contours
          @x_min = x_min
          @y_min = y_min
          @x_max = x_max
          @y_max = y_max

          # Because TTFunk is, at this time, a library for simply pulling
          # metrics out of font files, or for writing font subsets, we don't
          # really care what the contours are for simple glyphs. We just
          # care that we've got an entire glyph's definition. Also, a
          # bounding box could be nice to know. Since we've got all that
          # at this point, we don't need to worry about parsing the full
          # contents of the glyph.
        end

        def compound?
          false
        end

        def recode(_mapping)
          raw
        end
      end
    end
  end
end
