unless Array.method_defined? :permutation
  require 'backports/tools/arguments'
  require 'enumerator'

  class Array
    def permutation(num = Backports::Undefined)
      return to_enum(:permutation, num) unless block_given?
      num = num.equal?(Backports::Undefined) ?
            size :
            Backports.coerce_to_int(num)
      return self unless (0..size).include? num

      final_lambda = lambda do |partial, remain|
        yield partial
      end

      outer_lambda = (1..num).inject(final_lambda) do |proc, _|
        lambda do |partial, remain|
          remain.each_with_index do |val, i|
            new_remain = remain.dup
            new_remain.delete_at(i)
            proc.call(partial.dup << val, new_remain)
          end
        end
      end

      outer_lambda.call([], dup)
    end
  end
end
