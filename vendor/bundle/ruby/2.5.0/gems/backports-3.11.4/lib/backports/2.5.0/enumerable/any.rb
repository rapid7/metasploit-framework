if Enumerable.instance_method(:any?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  module Enumerable
    def any_with_pattern?(pattern = Backports::Undefined, &block)
      return any_without_pattern?(&block) if Backports::Undefined == pattern
      each_entry { |x| return true if pattern === x }
      false
    end
    Backports.alias_method_chain(self, :any?, :pattern)
  end
end

# MRI specializes `any?` for Array and Hash, so redefine those too
if Array.instance_method(:any?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Array
    def any_with_pattern?(pattern = Backports::Undefined, &block)
      return any_without_pattern?(&block) if Backports::Undefined == pattern
      each_entry { |x| return true if pattern === x }
      false
    end
    Backports.alias_method_chain(self, :any?, :pattern)
  end
end

if Hash.instance_method(:any?).arity == 0
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Hash
    def any_with_pattern?(pattern = Backports::Undefined, &block)
      return any_without_pattern?(&block) if Backports::Undefined == pattern
      each_entry { |x| return true if pattern === x }
      false
    end
    Backports.alias_method_chain(self, :any?, :pattern)
  end
end
