if Enumerable.instance_method(:all?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  module Enumerable
    def all_with_pattern?(pattern = Backports::Undefined, &block)
      return all_without_pattern?(&block) if Backports::Undefined == pattern
      each_entry { |x| return false unless pattern === x }
      true
    end
    Backports.alias_method_chain(self, :all?, :pattern)
  end
end
