unless Array.method_defined? :repeated_combination
  require 'backports/tools/arguments'
  require 'backports/1.8.7/array/index'

  class Array
    # Note: Combinations are not yielded in the same order as MRI.
    # This is not a bug; the spec states that the order is implementation dependent
    def repeated_combination(num)
      return to_enum(:repeated_combination, num) unless block_given?
      num = Backports.coerce_to_int(num)
      if num <= 0
        yield [] if num == 0
      else
        copy = dup
        indices = Array.new(num, 0)
        indices[-1] = size
        while dec = indices.index{|x| x != 0}
          indices.fill indices[dec]-1, 0, dec + 1
          yield copy.values_at(*indices)
        end
      end
      self
    end
  end
end
