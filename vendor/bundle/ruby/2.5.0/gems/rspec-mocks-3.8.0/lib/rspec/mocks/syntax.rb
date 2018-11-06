module RSpec
  module Mocks
    # @api private
    # Provides methods for enabling and disabling the available syntaxes
    # provided by rspec-mocks.
    module Syntax
      # @private
      def self.warn_about_should!
        @warn_about_should = true
      end

      # @private
      def self.warn_unless_should_configured(method_name , replacement="the new `:expect` syntax or explicitly enable `:should`")
        if @warn_about_should
          RSpec.deprecate(
            "Using `#{method_name}` from rspec-mocks' old `:should` syntax without explicitly enabling the syntax",
            :replacement => replacement
          )

          @warn_about_should = false
        end
      end

      # @api private
      # Enables the should syntax (`dbl.stub`, `dbl.should_receive`, etc).
      def self.enable_should(syntax_host=default_should_syntax_host)
        @warn_about_should = false if syntax_host == default_should_syntax_host
        return if should_enabled?(syntax_host)

        syntax_host.class_exec do
          def should_receive(message, opts={}, &block)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            ::RSpec::Mocks.expect_message(self, message, opts, &block)
          end

          def should_not_receive(message, &block)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            ::RSpec::Mocks.expect_message(self, message, {}, &block).never
          end

          def stub(message_or_hash, opts={}, &block)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            if ::Hash === message_or_hash
              message_or_hash.each { |message, value| stub(message).and_return value }
            else
              ::RSpec::Mocks.allow_message(self, message_or_hash, opts, &block)
            end
          end

          def unstub(message)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__, "`allow(...).to receive(...).and_call_original` or explicitly enable `:should`")
            ::RSpec::Mocks.space.proxy_for(self).remove_stub(message)
          end

          def stub_chain(*chain, &blk)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            ::RSpec::Mocks::StubChain.stub_chain_on(self, *chain, &blk)
          end

          def as_null_object
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            @_null_object = true
            ::RSpec::Mocks.space.proxy_for(self).as_null_object
          end

          def null_object?
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            defined?(@_null_object)
          end

          def received_message?(message, *args, &block)
            ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
            ::RSpec::Mocks.space.proxy_for(self).received_message?(message, *args, &block)
          end

          unless Class.respond_to? :any_instance
            Class.class_exec do
              def any_instance
                ::RSpec::Mocks::Syntax.warn_unless_should_configured(__method__)
                ::RSpec::Mocks.space.any_instance_proxy_for(self)
              end
            end
          end
        end
      end

      # @api private
      # Disables the should syntax (`dbl.stub`, `dbl.should_receive`, etc).
      def self.disable_should(syntax_host=default_should_syntax_host)
        return unless should_enabled?(syntax_host)

        syntax_host.class_exec do
          undef should_receive
          undef should_not_receive
          undef stub
          undef unstub
          undef stub_chain
          undef as_null_object
          undef null_object?
          undef received_message?
        end

        Class.class_exec do
          undef any_instance
        end
      end

      # @api private
      # Enables the expect syntax (`expect(dbl).to receive`, `allow(dbl).to receive`, etc).
      def self.enable_expect(syntax_host=::RSpec::Mocks::ExampleMethods)
        return if expect_enabled?(syntax_host)

        syntax_host.class_exec do
          def receive(method_name, &block)
            Matchers::Receive.new(method_name, block)
          end

          def receive_messages(message_return_value_hash)
            matcher = Matchers::ReceiveMessages.new(message_return_value_hash)
            matcher.warn_about_block if block_given?
            matcher
          end

          def receive_message_chain(*messages, &block)
            Matchers::ReceiveMessageChain.new(messages, &block)
          end

          def allow(target)
            AllowanceTarget.new(target)
          end

          def expect_any_instance_of(klass)
            AnyInstanceExpectationTarget.new(klass)
          end

          def allow_any_instance_of(klass)
            AnyInstanceAllowanceTarget.new(klass)
          end
        end

        RSpec::Mocks::ExampleMethods::ExpectHost.class_exec do
          def expect(target)
            ExpectationTarget.new(target)
          end
        end
      end

      # @api private
      # Disables the expect syntax (`expect(dbl).to receive`, `allow(dbl).to receive`, etc).
      def self.disable_expect(syntax_host=::RSpec::Mocks::ExampleMethods)
        return unless expect_enabled?(syntax_host)

        syntax_host.class_exec do
          undef receive
          undef receive_messages
          undef receive_message_chain
          undef allow
          undef expect_any_instance_of
          undef allow_any_instance_of
        end

        RSpec::Mocks::ExampleMethods::ExpectHost.class_exec do
          undef expect
        end
      end

      # @api private
      # Indicates whether or not the should syntax is enabled.
      def self.should_enabled?(syntax_host=default_should_syntax_host)
        syntax_host.method_defined?(:should_receive)
      end

      # @api private
      # Indicates whether or not the expect syntax is enabled.
      def self.expect_enabled?(syntax_host=::RSpec::Mocks::ExampleMethods)
        syntax_host.method_defined?(:allow)
      end

      # @api private
      # Determines where the methods like `should_receive`, and `stub` are added.
      def self.default_should_syntax_host
        # JRuby 1.7.4 introduces a regression whereby `defined?(::BasicObject) => nil`
        # yet `BasicObject` still exists and patching onto ::Object breaks things
        # e.g. SimpleDelegator expectations won't work
        #
        # See: https://github.com/jruby/jruby/issues/814
        if defined?(JRUBY_VERSION) && JRUBY_VERSION == '1.7.4' && RUBY_VERSION.to_f > 1.8
          return ::BasicObject
        end

        # On 1.8.7, Object.ancestors.last == Kernel but
        # things blow up if we include `RSpec::Mocks::Methods`
        # into Kernel...not sure why.
        return Object unless defined?(::BasicObject)

        # MacRuby has BasicObject but it's not the root class.
        return Object unless Object.ancestors.last == ::BasicObject

        ::BasicObject
      end
    end
  end
end

if defined?(BasicObject)
  # The legacy `:should` syntax adds the following methods directly to
  # `BasicObject` so that they are available off of any object. Note, however,
  # that this syntax does not always play nice with delegate/proxy objects.
  # We recommend you use the non-monkeypatching `:expect` syntax instead.
  # @see Class
  class BasicObject
    # @method should_receive
    # Sets an expectation that this object should receive a message before
    # the end of the example.
    #
    # @example
    #   logger = double('logger')
    #   thing_that_logs = ThingThatLogs.new(logger)
    #   logger.should_receive(:log)
    #   thing_that_logs.do_something_that_logs_a_message
    #
    # @note This is only available when you have enabled the `should` syntax.
    # @see RSpec::Mocks::ExampleMethods#expect

    # @method should_not_receive
    # Sets and expectation that this object should _not_ receive a message
    # during this example.
    # @see RSpec::Mocks::ExampleMethods#expect

    # @method stub
    # Tells the object to respond to the message with the specified value.
    #
    # @example
    #   counter.stub(:count).and_return(37)
    #   counter.stub(:count => 37)
    #   counter.stub(:count) { 37 }
    #
    # @note This is only available when you have enabled the `should` syntax.
    # @see RSpec::Mocks::ExampleMethods#allow

    # @method unstub
    # Removes a stub. On a double, the object will no longer respond to
    # `message`. On a real object, the original method (if it exists) is
    # restored.
    #
    # This is rarely used, but can be useful when a stub is set up during a
    # shared `before` hook for the common case, but you want to replace it
    # for a special case.
    #
    # @note This is only available when you have enabled the `should` syntax.

    # @method stub_chain
    # @overload stub_chain(method1, method2)
    # @overload stub_chain("method1.method2")
    # @overload stub_chain(method1, method_to_value_hash)
    #
    # Stubs a chain of methods.
    #
    # ## Warning:
    #
    # Chains can be arbitrarily long, which makes it quite painless to
    # violate the Law of Demeter in violent ways, so you should consider any
    # use of `stub_chain` a code smell. Even though not all code smells
    # indicate real problems (think fluent interfaces), `stub_chain` still
    # results in brittle examples.  For example, if you write
    # `foo.stub_chain(:bar, :baz => 37)` in a spec and then the
    # implementation calls `foo.baz.bar`, the stub will not work.
    #
    # @example
    #   double.stub_chain("foo.bar") { :baz }
    #   double.stub_chain(:foo, :bar => :baz)
    #   double.stub_chain(:foo, :bar) { :baz }
    #
    #     # Given any of ^^ these three forms ^^:
    #     double.foo.bar # => :baz
    #
    #     # Common use in Rails/ActiveRecord:
    #     Article.stub_chain("recent.published") { [Article.new] }
    #
    # @note This is only available when you have enabled the `should` syntax.
    # @see RSpec::Mocks::ExampleMethods#receive_message_chain

    # @method as_null_object
    # Tells the object to respond to all messages. If specific stub values
    # are declared, they'll work as expected. If not, the receiver is
    # returned.
    #
    # @note This is only available when you have enabled the `should` syntax.

    # @method null_object?
    # Returns true if this object has received `as_null_object`
    #
    # @note This is only available when you have enabled the `should` syntax.
  end
end

# The legacy `:should` syntax adds the `any_instance` to `Class`.
# We generally recommend you use the newer `:expect` syntax instead,
# which allows you to stub any instance of a class using
# `allow_any_instance_of(klass)` or mock any instance using
# `expect_any_instance_of(klass)`.
# @see BasicObject
class Class
  # @method any_instance
  # Used to set stubs and message expectations on any instance of a given
  # class. Returns a [Recorder](Recorder), which records messages like
  # `stub` and `should_receive` for later playback on instances of the
  # class.
  #
  # @example
  #   Car.any_instance.should_receive(:go)
  #   race = Race.new
  #   race.cars << Car.new
  #   race.go # assuming this delegates to all of its cars
  #           # this example would pass
  #
  #   Account.any_instance.stub(:balance) { Money.new(:USD, 25) }
  #   Account.new.balance # => Money.new(:USD, 25))
  #
  # @return [Recorder]
  #
  # @note This is only available when you have enabled the `should` syntax.
  # @see RSpec::Mocks::ExampleMethods#expect_any_instance_of
  # @see RSpec::Mocks::ExampleMethods#allow_any_instance_of
end
