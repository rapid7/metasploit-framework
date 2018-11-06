module RSpec
  module Mocks
    # @private
    class MethodDouble
      # @private
      attr_reader :method_name, :object, :expectations, :stubs, :method_stasher

      # @private
      def initialize(object, method_name, proxy)
        @method_name = method_name
        @object = object
        @proxy = proxy

        @original_visibility = nil
        @method_stasher = InstanceMethodStasher.new(object, method_name)
        @method_is_proxied = false
        @expectations = []
        @stubs = []
      end

      def original_implementation_callable
        # If original method is not present, uses the `method_missing`
        # handler of the object. This accounts for cases where the user has not
        # correctly defined `respond_to?`, and also 1.8 which does not provide
        # method handles for missing methods even if `respond_to?` is correct.
        @original_implementation_callable ||= original_method ||
          Proc.new do |*args, &block|
            @object.__send__(:method_missing, @method_name, *args, &block)
          end
      end

      alias_method :save_original_implementation_callable!, :original_implementation_callable

      def original_method
        @original_method ||=
          @method_stasher.original_method ||
          @proxy.original_method_handle_for(method_name)
      end

      # @private
      def visibility
        @proxy.visibility_for(@method_name)
      end

      # @private
      def object_singleton_class
        class << @object; self; end
      end

      # @private
      def configure_method
        @original_visibility = visibility
        @method_stasher.stash unless @method_is_proxied
        define_proxy_method
      end

      # @private
      def define_proxy_method
        return if @method_is_proxied

        save_original_implementation_callable!
        definition_target.class_exec(self, method_name, visibility) do |method_double, method_name, visibility|
          define_method(method_name) do |*args, &block|
            method_double.proxy_method_invoked(self, *args, &block)
          end
          __send__(visibility, method_name)
        end

        @method_is_proxied = true
      end

      # The implementation of the proxied method. Subclasses may override this
      # method to perform additional operations.
      #
      # @private
      def proxy_method_invoked(_obj, *args, &block)
        @proxy.message_received method_name, *args, &block
      end

      # @private
      def restore_original_method
        return show_frozen_warning if object_singleton_class.frozen?
        return unless @method_is_proxied

        remove_method_from_definition_target
        @method_stasher.restore if @method_stasher.method_is_stashed?
        restore_original_visibility

        @method_is_proxied = false
      end

      # @private
      def show_frozen_warning
        RSpec.warn_with(
          "WARNING: rspec-mocks was unable to restore the original `#{@method_name}` " \
          "method on #{@object.inspect} because it has been frozen.  If you reuse this " \
          "object, `#{@method_name}` will continue to respond with its stub implementation.",
          :call_site                      => nil,
          :use_spec_location_as_call_site => true
        )
      end

      # @private
      def restore_original_visibility
        return unless @original_visibility &&
          MethodReference.method_defined_at_any_visibility?(object_singleton_class, @method_name)

        object_singleton_class.__send__(@original_visibility, method_name)
      end

      # @private
      def verify
        expectations.each { |e| e.verify_messages_received }
      end

      # @private
      def reset
        restore_original_method
        clear
      end

      # @private
      def clear
        expectations.clear
        stubs.clear
      end

      # The type of message expectation to create has been extracted to its own
      # method so that subclasses can override it.
      #
      # @private
      def message_expectation_class
        MessageExpectation
      end

      # @private
      def add_expectation(error_generator, expectation_ordering, expected_from, opts, &implementation)
        configure_method
        expectation = message_expectation_class.new(error_generator, expectation_ordering,
                                                    expected_from, self, :expectation, opts, &implementation)
        expectations << expectation
        expectation
      end

      # @private
      def build_expectation(error_generator, expectation_ordering)
        expected_from = IGNORED_BACKTRACE_LINE
        message_expectation_class.new(error_generator, expectation_ordering, expected_from, self)
      end

      # @private
      def add_stub(error_generator, expectation_ordering, expected_from, opts={}, &implementation)
        configure_method
        stub = message_expectation_class.new(error_generator, expectation_ordering, expected_from,
                                             self, :stub, opts, &implementation)
        stubs.unshift stub
        stub
      end

      # A simple stub can only return a concrete value for a message, and
      # cannot match on arguments. It is used as an optimization over
      # `add_stub` / `add_expectation` where it is known in advance that this
      # is all that will be required of a stub, such as when passing attributes
      # to the `double` example method. They do not stash or restore existing method
      # definitions.
      #
      # @private
      def add_simple_stub(method_name, response)
        setup_simple_method_double method_name, response, stubs
      end

      # @private
      def add_simple_expectation(method_name, response, error_generator, backtrace_line)
        setup_simple_method_double method_name, response, expectations, error_generator, backtrace_line
      end

      # @private
      def setup_simple_method_double(method_name, response, collection, error_generator=nil, backtrace_line=nil)
        define_proxy_method

        me = SimpleMessageExpectation.new(method_name, response, error_generator, backtrace_line)
        collection.unshift me
        me
      end

      # @private
      def add_default_stub(*args, &implementation)
        return if stubs.any?
        add_stub(*args, &implementation)
      end

      # @private
      def remove_stub
        raise_method_not_stubbed_error if stubs.empty?
        remove_stub_if_present
      end

      # @private
      def remove_stub_if_present
        expectations.empty? ? reset : stubs.clear
      end

      # @private
      def raise_method_not_stubbed_error
        RSpec::Mocks.error_generator.raise_method_not_stubbed_error(method_name)
      end

      # In Ruby 2.0.0 and above prepend will alter the method lookup chain.
      # We use an object's singleton class to define method doubles upon,
      # however if the object has had its singleton class (as opposed to
      # its actual class) prepended too then the the method lookup chain
      # will look in the prepended module first, **before** the singleton
      # class.
      #
      # This code works around that by providing a mock definition target
      # that is either the singleton class, or if necessary, a prepended module
      # of our own.
      #
      if Support::RubyFeatures.module_prepends_supported?

        private

        # We subclass `Module` in order to be able to easily detect our prepended module.
        RSpecPrependedModule = Class.new(Module)

        def definition_target
          @definition_target ||= usable_rspec_prepended_module || object_singleton_class
        end

        def usable_rspec_prepended_module
          @proxy.prepended_modules_of_singleton_class.each do |mod|
            # If we have one of our modules prepended before one of the user's
            # modules that defines the method, use that, since our module's
            # definition will take precedence.
            return mod if RSpecPrependedModule === mod

            # If we hit a user module with the method defined first,
            # we must create a new prepend module, even if one exists later,
            # because ours will only take precedence if it comes first.
            return new_rspec_prepended_module if mod.method_defined?(method_name)
          end

          nil
        end

        def new_rspec_prepended_module
          RSpecPrependedModule.new.tap do |mod|
            object_singleton_class.__send__ :prepend, mod
          end
        end

      else

        private

        def definition_target
          object_singleton_class
        end

      end

    private

      def remove_method_from_definition_target
        definition_target.__send__(:remove_method, @method_name)
      rescue NameError
        # This can happen when the method has been monkeyed with by
        # something outside RSpec. This happens, for example, when
        # `file.write` has been stubbed, and then `file.reopen(other_io)`
        # is later called, as `File#reopen` appears to redefine `write`.
        #
        # Note: we could avoid rescuing this by checking
        # `definition_target.instance_method(@method_name).owner == definition_target`,
        # saving us from the cost of the expensive exception, but this error is
        # extremely rare (it was discovered on 2014-12-30, only happens on
        # RUBY_VERSION < 2.0 and our spec suite only hits this condition once),
        # so we'd rather avoid the cost of that check for every method double,
        # and risk the rare situation where this exception will get raised.
        RSpec.warn_with(
          "WARNING: RSpec could not fully restore #{@object.inspect}." \
          "#{@method_name}, possibly because the method has been redefined " \
          "by something outside of RSpec."
        )
      end
    end
  end
end
