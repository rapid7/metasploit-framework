
module RKelly
  # Represents a character position in source code.
  #
  # It's a value object - it can't be modified.
  class CharPos
    attr_reader :line, :char, :index

    def initialize(line, char, index)
      @line = line
      @char = char
      @index = index
    end

    # Creates a new character position that's a given string away from
    # this one.
    def next(string)
      if string.include?("\n")
        lines = string.split(/\n/, -1)
        CharPos.new(@line + lines.length - 1, lines.last.length, @index + string.length)
      else
        CharPos.new(@line, @char + string.length, @index + string.length)
      end
    end

    def to_s
      "{line:#{@line} char:#{@char} (#{@index})}"
    end

    alias_method :inspect, :to_s

    # A re-usable empty position
    EMPTY = CharPos.new(1,0,-1)
  end
end
