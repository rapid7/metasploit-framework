require 'backports/1.8.7/enumerable/one'

if Enumerable.instance_method(:one?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  module Enumerable
    def one_with_pattern?(pattern = Backports::Undefined, &block)
      return one_without_pattern?(&block) if Backports::Undefined == pattern
      found_one = false
      each_entry do |o|
        if pattern === o
          return false if found_one
          found_one = true
        end
      end
      found_one
    end
    Backports.alias_method_chain(self, :one?, :pattern)
  end
end
