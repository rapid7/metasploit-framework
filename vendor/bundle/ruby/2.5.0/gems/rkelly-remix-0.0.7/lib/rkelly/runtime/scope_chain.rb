module RKelly
  class Runtime
    class ScopeChain
      include RKelly::JS

      def initialize(scope = Scope.new)
        @chain = [GlobalObject.new]
      end

      def <<(scope)
        @chain << scope
      end

      def has_property?(name)
        scope = @chain.reverse.find { |x|
          x.has_property?(name)
        }
        scope ? scope[name] : nil
      end
      
      def [](name)
        property = has_property?(name)
        return property if property
        @chain.last.properties[name]
      end

      def []=(name, value)
        @chain.last.properties[name] = value
      end

      def pop
        @chain.pop
      end

      def this
        @chain.last
      end

      def new_scope(&block)
        @chain << Scope.new
        result = yield(self)
        @chain.pop
        result
      end

      def return=(value)
        @chain.last.return = value
      end

      def return; @chain.last.return; end

      def returned?
        @chain.last.returned?
      end
    end
  end
end
