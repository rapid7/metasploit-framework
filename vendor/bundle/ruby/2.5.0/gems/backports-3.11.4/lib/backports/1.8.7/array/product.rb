unless Array.method_defined? :product
  require 'backports/tools/arguments'

  class Array
    def product(*arg)
      # Implementation notes: We build a block that will generate all the combinations
      # by building it up successively using "inject" and starting with one
      # responsible to append the values.
      #
      result = []

      arg.map!{|ary| Backports.coerce_to_ary(ary)}
      n = arg.inject(size) { |p, a| p * a.size }
      return [] if n == 0
      raise RangeError, "too big a product" if n > 1<<31
      arg.reverse! # to get the results in the same order as in MRI, vary the last argument first
      arg.push self

      outer_lambda = arg.inject(result.method(:push)) do |proc, values|
        lambda do |partial|
          values.each do |val|
            proc.call(partial.dup << val)
          end
        end
      end

      outer_lambda.call([])

      result
    end
  end
end
