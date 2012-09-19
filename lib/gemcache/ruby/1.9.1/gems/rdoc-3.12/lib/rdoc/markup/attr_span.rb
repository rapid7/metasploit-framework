##
# An array of attributes which parallels the characters in a string.

class RDoc::Markup::AttrSpan

  ##
  # Creates a new AttrSpan for +length+ characters

  def initialize(length)
    @attrs = Array.new(length, 0)
  end

  ##
  # Toggles +bits+ from +start+ to +length+
  def set_attrs(start, length, bits)
    for i in start ... (start+length)
      @attrs[i] |= bits
    end
  end

  ##
  # Accesses flags for character +n+

  def [](n)
    @attrs[n]
  end

end

