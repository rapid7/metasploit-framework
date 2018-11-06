module Pry::Config::Memoization
  MEMOIZED_METHODS = Hash.new {|h,k| h[k] = [] }

  module ClassMethods
    #
    # Defines one or more methods who return a constant value after being
    # called once.
    #
    # @example
    #   class Foo
    #     include Pry::Config::Memoization
    #     def_memoized({
    #       foo: proc {1+10},
    #       bar: proc{"aaa"<<"a"}
    #     })
    #   end
    #
    # @param [{String => Proc}] method_table
    #
    # @return [void]
    #
    def def_memoized(method_table)
      method_table.each do |method_name, method|
        define_method(method_name) do
          method_table[method_name] = instance_eval(&method) if method_table[method_name].equal? method
          method_table[method_name]
        end
      end
      MEMOIZED_METHODS[self] |= method_table.keys
    end
  end

  def self.included(mod)
    mod.extend(ClassMethods)
  end

  #
  # @return [Array<Symbol>]
  #   Returns the names of methods that have been defined by {ClassMethods#def_memoized}.
  #
  def memoized_methods
    MEMOIZED_METHODS[self.class]
  end
end
