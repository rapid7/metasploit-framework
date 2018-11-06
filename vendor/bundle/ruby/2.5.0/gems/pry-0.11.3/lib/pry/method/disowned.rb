class Pry
  class Method
    # A Disowned Method is one that's been removed from the class on which it was defined.
    #
    # e.g.
    # class C
    #   def foo
    #     C.send(:undefine_method, :foo)
    #     Pry::Method.from_binding(binding)
    #   end
    # end
    #
    # In this case we assume that the "owner" is the singleton class of the receiver.
    #
    # This occurs mainly in Sinatra applications.
    class Disowned < Method
      attr_reader :receiver, :name

      # Create a new Disowned method.
      #
      # @param [Object] receiver
      # @param [String] method_name
      def initialize(receiver, method_name, binding=nil)
        @receiver, @name = receiver, method_name
        @method = nil
      end

      # Is the method undefined? (aka `Disowned`)
      # @return [Boolean] true
      def undefined?
        true
      end

      # Can we get the source for this method?
      # @return [Boolean] false
      def source?
        false
      end

      # Get the hypothesized owner of the method.
      #
      # @return [Object]
      def owner
        class << receiver; self; end
      end

      # Raise a more useful error message instead of trying to forward to nil.
      def method_missing(meth_name, *args, &block)
        raise "Cannot call '#{meth_name}' on an undef'd method." if method(:name).respond_to?(meth_name)
        Object.instance_method(:method_missing).bind(self).call(meth_name, *args, &block)
      end
    end
  end
end
