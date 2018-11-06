if Enumerable.instance_method(:to_a).arity.zero?
  require 'backports/tools/alias_method_chain'
  require 'enumerator'

  module Enumerable
    def to_a_with_optional_arguments(*args)
      return to_a_without_optional_arguments if args.empty?
      to_enum(:each, *args).to_a
    end
    Backports.alias_method_chain self, :to_a, :optional_arguments
  end
end
