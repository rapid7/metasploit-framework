require 'time'
require 'date'

class String # :nodoc:
  def to_liquid
    self
  end
end

class Array  # :nodoc:
  def to_liquid
    self
  end
end

class Hash  # :nodoc:
  def to_liquid
    self
  end
end

class Numeric  # :nodoc:
  def to_liquid
    self
  end
end

class Time  # :nodoc:
  def to_liquid
    self
  end
end

class DateTime < Date  # :nodoc:
  def to_liquid
    self
  end
end

class Date  # :nodoc:
  def to_liquid
    self
  end
end

class TrueClass
  def to_liquid  # :nodoc:
    self
  end
end

class FalseClass
  def to_liquid # :nodoc:
    self
  end
end

class NilClass
  def to_liquid # :nodoc:
    self
  end
end
