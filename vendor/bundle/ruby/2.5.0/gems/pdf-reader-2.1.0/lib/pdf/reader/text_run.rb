# coding: utf-8

class PDF::Reader
  # A value object that represents one or more consecutive characters on a page.
  class TextRun
    include Comparable

    attr_reader :x, :y, :width, :font_size, :text

    alias :to_s :text

    def initialize(x, y, width, font_size, text)
      @x = x
      @y = y
      @width = width
      @font_size = font_size.floor
      @text = text
    end

    # Allows collections of TextRun objects to be sorted. They will be sorted
    # in order of their position on a cartesian plain - Top Left to Bottom Right
    def <=>(other)
      if x == other.x && y == other.y
        0
      elsif y < other.y
        1
      elsif y > other.y
        -1
      elsif x < other.x
        -1
      elsif x > other.x
        1
      end
    end

    def endx
      @endx ||= x + width
    end

    def mean_character_width
      @width / character_count
    end

    def mergable?(other)
      y.to_i == other.y.to_i && font_size == other.font_size && mergable_range.include?(other.x)
    end

    def +(other)
      raise ArgumentError, "#{other} cannot be merged with this run" unless mergable?(other)

      if (other.x - endx) <( font_size * 0.2)
        TextRun.new(x, y, other.endx - x, font_size, text + other.text)
      else
        TextRun.new(x, y, other.endx - x, font_size, "#{text} #{other.text}")
      end
    end

    def inspect
      "#{text} w:#{width} f:#{font_size} @#{x},#{y}"
    end

    private

    def mergable_range
      @mergable_range ||= Range.new(endx - 3, endx + font_size)
    end

    # Assume string encoding is marked correctly and we can trust String#size to return a
    # character count
    def character_count
      @text.size.to_f
    end
  end
end
