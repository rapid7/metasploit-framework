unless Float.method_defined? :prev_float
  require 'backports/tools/float_integer_conversion'
  require 'backports/1.9.2/float/infinity'

  class Float
    def prev_float
      return -Float::INFINITY if self == -Float::INFINITY
      Backports.integer_to_float(Backports.float_to_integer(self)-1)
    end
  end
end
