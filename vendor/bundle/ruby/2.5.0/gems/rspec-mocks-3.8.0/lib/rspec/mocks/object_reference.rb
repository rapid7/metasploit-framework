module RSpec
  module Mocks
    # @private
    class ObjectReference
      # Returns an appropriate Object or Module reference based
      # on the given argument.
      def self.for(object_module_or_name, allow_direct_object_refs=false)
        case object_module_or_name
        when Module
          if anonymous_module?(object_module_or_name)
            DirectObjectReference.new(object_module_or_name)
          else
            # Use a `NamedObjectReference` if it has a name because this
            # will use the original value of the constant in case it has
            # been stubbed.
            NamedObjectReference.new(name_of(object_module_or_name))
          end
        when String
          NamedObjectReference.new(object_module_or_name)
        else
          if allow_direct_object_refs
            DirectObjectReference.new(object_module_or_name)
          else
            raise ArgumentError,
                  "Module or String expected, got #{object_module_or_name.inspect}"
          end
        end
      end

      if Module.new.name.nil?
        def self.anonymous_module?(mod)
          !name_of(mod)
        end
      else # 1.8.7
        def self.anonymous_module?(mod)
          name_of(mod) == ""
        end
      end
      private_class_method :anonymous_module?

      def self.name_of(mod)
        MODULE_NAME_METHOD.bind(mod).call
      end
      private_class_method :name_of

      # @private
      MODULE_NAME_METHOD = Module.instance_method(:name)
    end

    # An implementation of rspec-mocks' reference interface.
    # Used when an object is passed to {ExampleMethods#object_double}, or
    # an anonymous class or module is passed to {ExampleMethods#instance_double}
    # or {ExampleMethods#class_double}.
    # Represents a reference to that object.
    # @see NamedObjectReference
    class DirectObjectReference
      # @param object [Object] the object to which this refers
      def initialize(object)
        @object = object
      end

      # @return [String] the object's description (via `#inspect`).
      def description
        @object.inspect
      end

      # Defined for interface parity with the other object reference
      # implementations. Raises an `ArgumentError` to indicate that `as_stubbed_const`
      # is invalid when passing an object argument to `object_double`.
      def const_to_replace
        raise ArgumentError,
              "Can not perform constant replacement with an anonymous object."
      end

      # The target of the verifying double (the object itself).
      #
      # @return [Object]
      def target
        @object
      end

      # Always returns true for an object as the class is defined.
      #
      # @return [true]
      def defined?
        true
      end

      # Yields if the reference target is loaded, providing a generic mechanism
      # to optionally run a bit of code only when a reference's target is
      # loaded.
      #
      # This specific implementation always yields because direct references
      # are always loaded.
      #
      # @yield [Object] the target of this reference.
      def when_loaded
        yield @object
      end
    end

    # An implementation of rspec-mocks' reference interface.
    # Used when a string is passed to {ExampleMethods#object_double},
    # and when a string, named class or named module is passed to
    # {ExampleMethods#instance_double}, or {ExampleMethods#class_double}.
    # Represents a reference to the object named (via a constant lookup)
    # by the string.
    # @see DirectObjectReference
    class NamedObjectReference
      # @param const_name [String] constant name
      def initialize(const_name)
        @const_name = const_name
      end

      # @return [Boolean] true if the named constant is defined, false otherwise.
      def defined?
        !!object
      end

      # @return [String] the constant name to replace with a double.
      def const_to_replace
        @const_name
      end
      alias description const_to_replace

      # @return [Object, nil] the target of the verifying double (the named object), or
      #   nil if it is not defined.
      def target
        object
      end

      # Yields if the reference target is loaded, providing a generic mechanism
      # to optionally run a bit of code only when a reference's target is
      # loaded.
      #
      # @yield [Object] the target object
      def when_loaded
        yield object if object
      end

    private

      def object
        return @object if defined?(@object)
        @object = Constant.original(@const_name).original_value
      end
    end
  end
end
