unless ((1..2).inject(:+) rescue false)
  require 'backports/tools/alias_method'
  require 'backports/tools/alias_method_chain'

  module Enumerable
    def inject_with_symbol(*args, &block)
      return inject_without_symbol(*args, &block) if block_given? && args.size <= 1
      method = args.pop
      inject_without_symbol(*args) {|memo, obj| memo.send(method, obj)}
    end
    Backports.alias_method_chain self, :inject, :symbol
  end

  Backports.alias_method Enumerable, :reduce, :inject
end
