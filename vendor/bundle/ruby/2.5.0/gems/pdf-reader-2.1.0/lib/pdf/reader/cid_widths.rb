# coding: utf-8
#

require 'forwardable'

class PDF::Reader
  # A Hash-like object that wraps the array of glyph widths in a CID font
  # and gives us a nice way to query it for specific widths.
  #
  # there are two ways to calculate a cidfont_glyph_width, that are defined
  # in Section 9.7.4.3 PDF 32000-1:2008 pp 271, the differences are remarked
  # on below. because of these difference that may be contained within the
  # same array, it is a bit difficult to parse this array.
  class CidWidths
    extend Forwardable

    # Graphics State Operators
    def_delegators :@widths, :[], :fetch

    def initialize(default, array)
      @widths = parse_array(default, array.dup)
    end

    private

    def parse_array(default, array)
      widths  = Hash.new(default)
      params = []
      while array.size > 0
        params << array.shift

        if params.size == 2 && params.last.is_a?(Array)
          widths.merge! parse_first_form(params.first, params.last)
          params = []
        elsif params.size == 3
          widths.merge! parse_second_form(params[0], params[1], params[2])
          params = []
        end
      end
      widths
    end

    # this is the form 10 [234 63 234 346 47 234] where width of index 10 is
    # 234, index 11 is 63, etc
    def parse_first_form(first, widths)
      widths.inject({}) { |accum, glyph_width|
        accum[first + accum.size] = glyph_width
        accum
      }
    end

    # this is the form 10 20 123 where all index between 10 and 20 have width 123
    def parse_second_form(first, final, width)
      (first..final).inject({}) { |accum, index|
        accum[index] = width
        accum
      }
    end

  end
end
