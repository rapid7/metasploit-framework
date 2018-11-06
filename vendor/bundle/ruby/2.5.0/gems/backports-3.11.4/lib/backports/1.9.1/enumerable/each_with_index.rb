if Enumerable.instance_method(:each_with_index).arity.zero?
  require 'backports/tools/alias_method_chain'
  require 'enumerator'

  module Enumerable
    def each_with_index_with_optional_args_and_block(*args)
      return to_enum(:each_with_index, *args) unless block_given?
      idx = 0
      each(*args) { |o| yield(o, idx); idx += 1 }
      self
    end
    Backports.alias_method_chain self, :each_with_index, :optional_args_and_block
  end
end
