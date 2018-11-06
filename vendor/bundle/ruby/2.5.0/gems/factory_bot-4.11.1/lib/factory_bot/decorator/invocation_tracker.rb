module FactoryBot
  class Decorator
    class InvocationTracker < Decorator
      def initialize(component)
        super
        @invoked_methods = []
      end

      def method_missing(name, *args, &block)
        @invoked_methods << name
        super
      end

      def __invoked_methods__
        @invoked_methods.uniq
      end
    end
  end
end
