module RKelly
  module Nodes
    class ResolveNode < Node
      def ==(other)
        return true if super
        if @value =~ /^[A-Z]/
          place = [Object, Module, RKelly::Nodes].find { |x|
            x.const_defined?(@value.to_sym)
          }
          return false unless place
          klass = place.const_get(@value.to_sym)
          return true if klass && other.is_a?(klass) || other.value.is_a?(klass)
        end
        false
      end
      alias :=~ :==
    end
  end
end
