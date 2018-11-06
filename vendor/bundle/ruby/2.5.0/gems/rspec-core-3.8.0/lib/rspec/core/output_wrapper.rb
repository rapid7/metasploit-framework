module RSpec
  module Core
    # @private
    class OutputWrapper
      # @private
      attr_accessor :output

      # @private
      def initialize(output)
        @output = output
      end

      def respond_to?(name, priv=false)
        output.respond_to?(name, priv)
      end

      def method_missing(name, *args, &block)
        output.send(name, *args, &block)
      end

      # Redirect calls for IO interface methods
      IO.instance_methods(false).each do |method|
        define_method(method) do |*args, &block|
          output.send(method, *args, &block)
        end
      end
    end
  end
end
