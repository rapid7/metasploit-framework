RSpec::Support.require_rspec_support 'comparable_version'

module RSpec
  module Mocks
    # Represents a method on an object that may or may not be defined.
    # The method may be an instance method on a module or a method on
    # any object.
    #
    # @private
    class MethodReference
      def self.for(object_reference, method_name)
        new(object_reference, method_name)
      end

      def initialize(object_reference, method_name)
        @object_reference = object_reference
        @method_name = method_name
      end

      # A method is implemented if sending the message does not result in
      # a `NoMethodError`. It might be dynamically implemented by
      # `method_missing`.
      def implemented?
        @object_reference.when_loaded do |m|
          method_implemented?(m)
        end
      end

      # Returns true if we definitively know that sending the method
      # will result in a `NoMethodError`.
      #
      # This is not simply the inverse of `implemented?`: there are
      # cases when we don't know if a method is implemented and
      # both `implemented?` and `unimplemented?` will return false.
      def unimplemented?
        @object_reference.when_loaded do |_m|
          return !implemented?
        end

        # If it's not loaded, then it may be implemented but we can't check.
        false
      end

      # A method is defined if we are able to get a `Method` object for it.
      # In that case, we can assert against metadata like the arity.
      def defined?
        @object_reference.when_loaded do |m|
          method_defined?(m)
        end
      end

      def with_signature
        return unless (original = original_method)
        yield Support::MethodSignature.new(original)
      end

      def visibility
        @object_reference.when_loaded do |m|
          return visibility_from(m)
        end

        # When it's not loaded, assume it's public. We don't want to
        # wrongly treat the method as private.
        :public
      end

      def self.instance_method_visibility_for(klass, method_name)
        if klass.public_method_defined?(method_name)
          :public
        elsif klass.private_method_defined?(method_name)
          :private
        elsif klass.protected_method_defined?(method_name)
          :protected
        end
      end

      class << self
        alias method_defined_at_any_visibility? instance_method_visibility_for
      end

      def self.method_visibility_for(object, method_name)
        vis = instance_method_visibility_for(class << object; self; end, method_name)

        # If the method is not defined on the class, `instance_method_visibility_for`
        # returns `nil`. However, it may be handled dynamically by `method_missing`,
        # so here we check `respond_to` (passing false to not check private methods).
        #
        # This only considers the public case, but I don't think it's possible to
        # write `method_missing` in such a way that it handles a dynamic message
        # with private or protected visibility. Ruby doesn't provide you with
        # the caller info.
        return vis unless vis.nil?

        proxy = RSpec::Mocks.space.proxy_for(object)
        respond_to = proxy.method_double_if_exists_for_message(:respond_to?)

        visible = respond_to && respond_to.original_method.call(method_name) ||
          object.respond_to?(method_name)

        return :public if visible
      end

    private

      def original_method
        @object_reference.when_loaded do |m|
          self.defined? && find_method(m)
        end
      end
    end

    # @private
    class InstanceMethodReference < MethodReference
    private

      def method_implemented?(mod)
        MethodReference.method_defined_at_any_visibility?(mod, @method_name)
      end

      # Ideally, we'd use `respond_to?` for `method_implemented?` but we need a
      # reference to an instance to do that and we don't have one.  Note that
      # we may get false negatives: if the method is implemented via
      # `method_missing`, we'll return `false` even though it meets our
      # definition of "implemented". However, it's the best we can do.
      alias method_defined? method_implemented?

      # works around the fact that repeated calls for method parameters will
      # falsely return empty arrays on JRuby in certain circumstances, this
      # is necessary here because we can't dup/clone UnboundMethods.
      #
      # This is necessary due to a bug in JRuby prior to 1.7.5 fixed in:
      # https://github.com/jruby/jruby/commit/99a0613fe29935150d76a9a1ee4cf2b4f63f4a27
      if RUBY_PLATFORM == 'java' && RSpec::Support::ComparableVersion.new(JRUBY_VERSION) < '1.7.5'
        def find_method(mod)
          mod.dup.instance_method(@method_name)
        end
      else
        def find_method(mod)
          mod.instance_method(@method_name)
        end
      end

      def visibility_from(mod)
        MethodReference.instance_method_visibility_for(mod, @method_name)
      end
    end

    # @private
    class ObjectMethodReference < MethodReference
      def self.for(object_reference, method_name)
        if ClassNewMethodReference.applies_to?(method_name) { object_reference.when_loaded { |o| o } }
          ClassNewMethodReference.new(object_reference, method_name)
        else
          super
        end
      end

    private

      def method_implemented?(object)
        object.respond_to?(@method_name, true)
      end

      def method_defined?(object)
        (class << object; self; end).method_defined?(@method_name)
      end

      def find_method(object)
        object.method(@method_name)
      end

      def visibility_from(object)
        MethodReference.method_visibility_for(object, @method_name)
      end
    end

    # When a class's `.new` method is stubbed, we want to use the method
    # signature from `#initialize` because `.new`'s signature is a generic
    # `def new(*args)` and it simply delegates to `#initialize` and forwards
    # all args...so the method with the actually used signature is `#initialize`.
    #
    # This method reference implementation handles that specific case.
    # @private
    class ClassNewMethodReference < ObjectMethodReference
      def self.applies_to?(method_name)
        return false unless method_name == :new
        klass = yield
        return false unless klass.respond_to?(:new, true)

        # We only want to apply our special logic to normal `new` methods.
        # Methods that the user has monkeyed with should be left as-is.
        ::RSpec::Support.method_handle_for(klass, :new).owner == ::Class
      end

      def with_signature
        @object_reference.when_loaded do |klass|
          yield Support::MethodSignature.new(klass.instance_method(:initialize))
        end
      end
    end
  end
end
