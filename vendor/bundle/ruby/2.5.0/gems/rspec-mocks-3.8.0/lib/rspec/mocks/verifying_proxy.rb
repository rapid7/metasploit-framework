RSpec::Support.require_rspec_mocks 'verifying_message_expectation'
RSpec::Support.require_rspec_mocks 'method_reference'

module RSpec
  module Mocks
    # @private
    class CallbackInvocationStrategy
      def call(doubled_module)
        RSpec::Mocks.configuration.verifying_double_callbacks.each do |block|
          block.call doubled_module
        end
      end
    end

    # @private
    class NoCallbackInvocationStrategy
      def call(_doubled_module)
      end
    end

    # @private
    module VerifyingProxyMethods
      def add_stub(method_name, opts={}, &implementation)
        ensure_implemented(method_name)
        super
      end

      def add_simple_stub(method_name, *args)
        ensure_implemented(method_name)
        super
      end

      def add_message_expectation(method_name, opts={}, &block)
        ensure_implemented(method_name)
        super
      end

      def ensure_implemented(method_name)
        return unless method_reference[method_name].unimplemented?

        @error_generator.raise_unimplemented_error(
          @doubled_module,
          method_name,
          @object
        )
      end

      def ensure_publicly_implemented(method_name, _object)
        ensure_implemented(method_name)
        visibility = method_reference[method_name].visibility

        return if visibility == :public
        @error_generator.raise_non_public_error(method_name, visibility)
      end
    end

    # A verifying proxy mostly acts like a normal proxy, except that it
    # contains extra logic to try and determine the validity of any expectation
    # set on it. This includes whether or not methods have been defined and the
    # validatiy of arguments on method calls.
    #
    # In all other ways this behaves like a normal proxy. It only adds the
    # verification behaviour to specific methods then delegates to the parent
    # implementation.
    #
    # These checks are only activated if the doubled class has already been
    # loaded, otherwise they are disabled. This allows for testing in
    # isolation.
    #
    # @private
    class VerifyingProxy < TestDoubleProxy
      include VerifyingProxyMethods

      def initialize(object, order_group, doubled_module, method_reference_class)
        super(object, order_group)
        @object                 = object
        @doubled_module         = doubled_module
        @method_reference_class = method_reference_class

        # A custom method double is required to pass through a way to lookup
        # methods to determine their parameters. This is only relevant if the doubled
        # class is loaded.
        @method_doubles = Hash.new do |h, k|
          h[k] = VerifyingMethodDouble.new(@object, k, self, method_reference[k])
        end
      end

      def method_reference
        @method_reference ||= Hash.new do |h, k|
          h[k] = @method_reference_class.for(@doubled_module, k)
        end
      end

      def visibility_for(method_name)
        method_reference[method_name].visibility
      end

      def validate_arguments!(method_name, args)
        @method_doubles[method_name].validate_arguments!(args)
      end
    end

    # @private
    DEFAULT_CALLBACK_INVOCATION_STRATEGY = CallbackInvocationStrategy.new

    # @private
    class VerifyingPartialDoubleProxy < PartialDoubleProxy
      include VerifyingProxyMethods

      def initialize(object, expectation_ordering, optional_callback_invocation_strategy=DEFAULT_CALLBACK_INVOCATION_STRATEGY)
        super(object, expectation_ordering)
        @doubled_module = DirectObjectReference.new(object)

        # A custom method double is required to pass through a way to lookup
        # methods to determine their parameters.
        @method_doubles = Hash.new do |h, k|
          h[k] = VerifyingExistingMethodDouble.for(object, k, self)
        end

        optional_callback_invocation_strategy.call(@doubled_module)
      end

      def ensure_implemented(_method_name)
        return if Mocks.configuration.temporarily_suppress_partial_double_verification
        super
      end

      def method_reference
        @method_doubles
      end
    end

    # @private
    class VerifyingPartialClassDoubleProxy < VerifyingPartialDoubleProxy
      include PartialClassDoubleProxyMethods
    end

    # @private
    class VerifyingMethodDouble < MethodDouble
      def initialize(object, method_name, proxy, method_reference)
        super(object, method_name, proxy)
        @method_reference = method_reference
      end

      def message_expectation_class
        VerifyingMessageExpectation
      end

      def add_expectation(*args, &block)
        # explict params necessary for 1.8.7 see #626
        super(*args, &block).tap { |x| x.method_reference = @method_reference }
      end

      def add_stub(*args, &block)
        # explict params necessary for 1.8.7 see #626
        super(*args, &block).tap { |x| x.method_reference = @method_reference }
      end

      def proxy_method_invoked(obj, *args, &block)
        validate_arguments!(args)
        super
      end

      def validate_arguments!(actual_args)
        @method_reference.with_signature do |signature|
          verifier = Support::StrictSignatureVerifier.new(signature, actual_args)
          raise ArgumentError, verifier.error_message unless verifier.valid?
        end
      end
    end

    # A VerifyingMethodDouble fetches the method to verify against from the
    # original object, using a MethodReference. This works for pure doubles,
    # but when the original object is itself the one being modified we need to
    # collapse the reference and the method double into a single object so that
    # we can access the original pristine method definition.
    #
    # @private
    class VerifyingExistingMethodDouble < VerifyingMethodDouble
      def initialize(object, method_name, proxy)
        super(object, method_name, proxy, self)

        @valid_method = object.respond_to?(method_name, true)

        # Trigger an eager find of the original method since if we find it any
        # later we end up getting a stubbed method with incorrect arity.
        save_original_implementation_callable!
      end

      def with_signature
        yield Support::MethodSignature.new(original_implementation_callable)
      end

      def unimplemented?
        !@valid_method
      end

      def self.for(object, method_name, proxy)
        if ClassNewMethodReference.applies_to?(method_name) { object }
          VerifyingExistingClassNewMethodDouble
        elsif Mocks.configuration.temporarily_suppress_partial_double_verification
          MethodDouble
        else
          self
        end.new(object, method_name, proxy)
      end
    end

    # Used in place of a `VerifyingExistingMethodDouble` for the specific case
    # of mocking or stubbing a `new` method on a class. In this case, we substitute
    # the method signature from `#initialize` since new's signature is just `*args`.
    #
    # @private
    class VerifyingExistingClassNewMethodDouble < VerifyingExistingMethodDouble
      def with_signature
        yield Support::MethodSignature.new(object.instance_method(:initialize))
      end
    end
  end
end
