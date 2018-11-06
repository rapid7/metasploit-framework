# Monkey patch to add stubbed string encoding functions to Ruby 1.8

class String
  def force_encoding(encoding)
    @encoding = encoding
    self
  end

  def encoding
    @encoding ||= Encoding::ASCII_8BIT
  end

  def encode(encoding)
    new = self.dup
    new.force_encoding(encoding)
  end
end

class Encoding
  def initialize(name)
    @name = name
  end

  def to_s
    @name
  end
  
  def name
    @name
  end

  UTF_8 = Encoding.new("UTF-8")
  ASCII_8BIT = Encoding.new("ASCII-8BIT")
end
