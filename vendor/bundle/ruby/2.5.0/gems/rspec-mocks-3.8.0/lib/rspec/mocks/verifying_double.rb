RSpec::Support.require_rspec_mocks 'verifying_proxy'

module RSpec
  module Mocks
    # @private
    module VerifyingDouble
      def respond_to?(message, include_private=false)
        return super unless null_object?

        method_ref = __mock_proxy.method_reference[message]

        case method_ref.visibility
        when :public    then true
        when :private   then include_private
        when :protected then include_private || RUBY_VERSION.to_f < 2.0
        else !method_ref.unimplemented?
        end
      end

      def method_missing(message, *args, &block)
        # Null object conditional is an optimization. If not a null object,
        # validity of method expectations will have been checked at definition
        # time.
        if null_object?
          if @__sending_message == message
            __mock_proxy.ensure_implemented(message)
          else
            __mock_proxy.ensure_publicly_implemented(message, self)
          end

          __mock_proxy.validate_arguments!(message, args)
        end

        super
      end

      # @private
      module SilentIO
        def self.method_missing(*); end
        def self.respond_to?(*)
          true
        end
      end

      # Redefining `__send__` causes ruby to issue a warning.
      old, $stderr = $stderr, SilentIO
      def __send__(name, *args, &block)
        @__sending_message = name
        super
      ensure
        @__sending_message = nil
      end
      $stderr = old

      def send(name, *args, &block)
        __send__(name, *args, &block)
      end

      def initialize(doubled_module, *args)
        @doubled_module = doubled_module

        possible_name = args.first
        name = if String === possible_name || Symbol === possible_name
                 args.shift
               end

        super(name, *args)
        @__sending_message = nil
      end
    end

    # A mock providing a custom proxy that can verify the validity of any
    # method stubs or expectations against the public instance methods of the
    # given class.
    #
    # @private
    class InstanceVerifyingDouble
      include TestDouble
      include VerifyingDouble

      def __build_mock_proxy(order_group)
        VerifyingProxy.new(self, order_group,
                           @doubled_module,
                           InstanceMethodReference
        )
      end
    end

    # An awkward module necessary because we cannot otherwise have
    # ClassVerifyingDouble inherit from Module and still share these methods.
    #
    # @private
    module ObjectVerifyingDoubleMethods
      include TestDouble
      include VerifyingDouble

      def as_stubbed_const(options={})
        ConstantMutator.stub(@doubled_module.const_to_replace, self, options)
        self
      end

    private

      def __build_mock_proxy(order_group)
        VerifyingProxy.new(self, order_group,
                           @doubled_module,
                           ObjectMethodReference
        )
      end
    end

    # Similar to an InstanceVerifyingDouble, except that it verifies against
    # public methods of the given object.
    #
    # @private
    class ObjectVerifyingDouble
      include ObjectVerifyingDoubleMethods
    end

    # Effectively the same as an ObjectVerifyingDouble (since a class is a type
    # of object), except with Module in the inheritance chain so that
    # transferring nested constants to work.
    #
    # @private
    class ClassVerifyingDouble < Module
      include ObjectVerifyingDoubleMethods
    end
  end
end
