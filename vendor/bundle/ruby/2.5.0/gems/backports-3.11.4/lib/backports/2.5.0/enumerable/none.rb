require 'backports/1.8.7/enumerable/none'

if Enumerable.instance_method(:none?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  module Enumerable
    def none_with_pattern?(pattern = Backports::Undefined, &block)
      return none_without_pattern?(&block) if Backports::Undefined == pattern
      each_entry { |x| return false if pattern === x }
      true
    end
    Backports.alias_method_chain(self, :none?, :pattern)
  end
end
