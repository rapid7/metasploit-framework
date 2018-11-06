if ([1].product([2]){break false} rescue true)
  require 'backports/tools/arguments'
  require 'backports/tools/alias_method_chain'
  require 'backports/1.8.7/array/product'

  class Array
    def product_with_block(*arg, &block)
      return product_without_block(*arg) unless block_given?
      # Same implementation as 1.8.7, but yielding
      arg.map!{|ary| Backports.coerce_to_ary(ary)}
      arg.reverse! # to get the results in the same order as in MRI, vary the last argument first
      arg.push self

      outer_lambda = arg.inject(block) do |proc, values|
        lambda do |partial|
          values.each do |val|
            proc.call(partial.dup << val)
          end
        end
      end

      outer_lambda.call([])
      self
    end
    Backports.alias_method_chain self, :product, :block
  end
end
