unless Float.method_defined? :next_float
  require 'backports/tools/float_integer_conversion'

  class Float
    def next_float
      return Float::INFINITY if self == Float::INFINITY
      r = Backports.integer_to_float(Backports.float_to_integer(self)+1)
      r == 0 ? -0.0 : r # Map +0.0 to -0.0
    end
  end
end
