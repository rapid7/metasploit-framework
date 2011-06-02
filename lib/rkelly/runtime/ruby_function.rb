module RKelly
  class Runtime
    class RubyFunction
      def initialize(&block)
        @code = block
      end

      def call(chain, *args)
        @code.call(*args)
      end
    end
  end
end
