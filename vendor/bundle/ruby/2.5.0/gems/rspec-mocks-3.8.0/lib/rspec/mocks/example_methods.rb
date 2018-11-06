RSpec::Support.require_rspec_mocks 'object_reference'

module RSpec
  module Mocks
    # Contains methods intended to be used from within code examples.
    # Mix this in to your test context (such as a test framework base class)
    # to use rspec-mocks with your test framework. If you're using rspec-core,
    # it'll take care of doing this for you.
    module ExampleMethods
      include RSpec::Mocks::ArgumentMatchers

      # @overload double()
      # @overload double(name)
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload double(stubs)
      #   @param stubs (Hash) hash of message/return-value pairs
      # @overload double(name, stubs)
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs (Hash) hash of message/return-value pairs
      # @return (Double)
      #
      # Constructs an instance of [RSpec::Mocks::Double](RSpec::Mocks::Double) configured
      # with an optional name, used for reporting in failure messages, and an optional
      # hash of message/return-value pairs.
      #
      # @example
      #   book = double("book", :title => "The RSpec Book")
      #   book.title #=> "The RSpec Book"
      #
      #   card = double("card", :suit => "Spades", :rank => "A")
      #   card.suit  #=> "Spades"
      #   card.rank  #=> "A"
      #
      def double(*args)
        ExampleMethods.declare_double(Double, *args)
      end

      # @overload instance_double(doubled_class)
      #   @param doubled_class [String, Class]
      # @overload instance_double(doubled_class, name)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload instance_double(doubled_class, stubs)
      #   @param doubled_class [String, Class]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload instance_double(doubled_class, name, stubs)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return InstanceVerifyingDouble
      #
      # Constructs a test double against a specific class. If the given class
      # name has been loaded, only instance methods defined on the class are
      # allowed to be stubbed. In all other ways it behaves like a
      # [double](double).
      def instance_double(doubled_class, *args)
        ref = ObjectReference.for(doubled_class)
        ExampleMethods.declare_verifying_double(InstanceVerifyingDouble, ref, *args)
      end

      # @overload class_double(doubled_class)
      #   @param doubled_class [String, Module]
      # @overload class_double(doubled_class, name)
      #   @param doubled_class [String, Module]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload class_double(doubled_class, stubs)
      #   @param doubled_class [String, Module]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload class_double(doubled_class, name, stubs)
      #   @param doubled_class [String, Module]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return ClassVerifyingDouble
      #
      # Constructs a test double against a specific class. If the given class
      # name has been loaded, only class methods defined on the class are
      # allowed to be stubbed. In all other ways it behaves like a
      # [double](double).
      def class_double(doubled_class, *args)
        ref = ObjectReference.for(doubled_class)
        ExampleMethods.declare_verifying_double(ClassVerifyingDouble, ref, *args)
      end

      # @overload object_double(object_or_name)
      #   @param object_or_name [String, Object]
      # @overload object_double(object_or_name, name)
      #   @param object_or_name [String, Object]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload object_double(object_or_name, stubs)
      #   @param object_or_name [String, Object]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload object_double(object_or_name, name, stubs)
      #   @param object_or_name [String, Object]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return ObjectVerifyingDouble
      #
      # Constructs a test double against a specific object. Only the methods
      # the object responds to are allowed to be stubbed. If a String argument
      # is provided, it is assumed to reference a constant object which is used
      # for verification. In all other ways it behaves like a [double](double).
      def object_double(object_or_name, *args)
        ref = ObjectReference.for(object_or_name, :allow_direct_object_refs)
        ExampleMethods.declare_verifying_double(ObjectVerifyingDouble, ref, *args)
      end

      # @overload spy()
      # @overload spy(name)
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload spy(stubs)
      #   @param stubs (Hash) hash of message/return-value pairs
      # @overload spy(name, stubs)
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs (Hash) hash of message/return-value pairs
      # @return (Double)
      #
      # Constructs a test double that is optimized for use with
      # `have_received`. With a normal double one has to stub methods in order
      # to be able to spy them. A spy automatically spies on all methods.
      def spy(*args)
        double(*args).as_null_object
      end

      # @overload instance_spy(doubled_class)
      #   @param doubled_class [String, Class]
      # @overload instance_spy(doubled_class, name)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload instance_spy(doubled_class, stubs)
      #   @param doubled_class [String, Class]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload instance_spy(doubled_class, name, stubs)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return InstanceVerifyingDouble
      #
      # Constructs a test double that is optimized for use with `have_received`
      # against a specific class. If the given class name has been loaded, only
      # instance methods defined on the class are allowed to be stubbed.  With
      # a normal double one has to stub methods in order to be able to spy
      # them. An instance_spy automatically spies on all instance methods to
      # which the class responds.
      def instance_spy(*args)
        instance_double(*args).as_null_object
      end

      # @overload object_spy(object_or_name)
      #   @param object_or_name [String, Object]
      # @overload object_spy(object_or_name, name)
      #   @param object_or_name [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload object_spy(object_or_name, stubs)
      #   @param object_or_name [String, Object]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload object_spy(object_or_name, name, stubs)
      #   @param object_or_name [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return ObjectVerifyingDouble
      #
      # Constructs a test double that is optimized for use with `have_received`
      # against a specific object. Only instance methods defined on the object
      # are allowed to be stubbed.  With a normal double one has to stub
      # methods in order to be able to spy them. An object_spy automatically
      # spies on all methods to which the object responds.
      def object_spy(*args)
        object_double(*args).as_null_object
      end

      # @overload class_spy(doubled_class)
      #   @param doubled_class [String, Module]
      # @overload class_spy(doubled_class, name)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      # @overload class_spy(doubled_class, stubs)
      #   @param doubled_class [String, Module]
      #   @param stubs [Hash] hash of message/return-value pairs
      # @overload class_spy(doubled_class, name, stubs)
      #   @param doubled_class [String, Class]
      #   @param name [String/Symbol] name or description to be used in failure messages
      #   @param stubs [Hash] hash of message/return-value pairs
      # @return ClassVerifyingDouble
      #
      # Constructs a test double that is optimized for use with `have_received`
      # against a specific class. If the given class name has been loaded,
      # only class methods defined on the class are allowed to be stubbed.
      # With a normal double one has to stub methods in order to be able to spy
      # them. An class_spy automatically spies on all class methods to which the
      # class responds.
      def class_spy(*args)
        class_double(*args).as_null_object
      end

      # Disables warning messages about expectations being set on nil.
      #
      # By default warning messages are issued when expectations are set on
      # nil.  This is to prevent false-positives and to catch potential bugs
      # early on.
      # @deprecated Use {RSpec::Mocks::Configuration#allow_message_expectations_on_nil} instead.
      def allow_message_expectations_on_nil
        RSpec::Mocks.space.proxy_for(nil).warn_about_expectations = false
      end

      # Stubs the named constant with the given value.
      # Like method stubs, the constant will be restored
      # to its original value (or lack of one, if it was
      # undefined) when the example completes.
      #
      # @param constant_name [String] The fully qualified name of the constant. The current
      #   constant scoping at the point of call is not considered.
      # @param value [Object] The value to make the constant refer to. When the
      #   example completes, the constant will be restored to its prior state.
      # @param options [Hash] Stubbing options.
      # @option options :transfer_nested_constants [Boolean, Array<Symbol>] Determines
      #   what nested constants, if any, will be transferred from the original value
      #   of the constant to the new value of the constant. This only works if both
      #   the original and new values are modules (or classes).
      # @return [Object] the stubbed value of the constant
      #
      # @example
      #   stub_const("MyClass", Class.new) # => Replaces (or defines) MyClass with a new class object.
      #   stub_const("SomeModel::PER_PAGE", 5) # => Sets SomeModel::PER_PAGE to 5.
      #
      #   class CardDeck
      #     SUITS = [:Spades, :Diamonds, :Clubs, :Hearts]
      #     NUM_CARDS = 52
      #   end
      #
      #   stub_const("CardDeck", Class.new)
      #   CardDeck::SUITS # => uninitialized constant error
      #   CardDeck::NUM_CARDS # => uninitialized constant error
      #
      #   stub_const("CardDeck", Class.new, :transfer_nested_constants => true)
      #   CardDeck::SUITS # => our suits array
      #   CardDeck::NUM_CARDS # => 52
      #
      #   stub_const("CardDeck", Class.new, :transfer_nested_constants => [:SUITS])
      #   CardDeck::SUITS # => our suits array
      #   CardDeck::NUM_CARDS # => uninitialized constant error
      def stub_const(constant_name, value, options={})
        ConstantMutator.stub(constant_name, value, options)
      end

      # Hides the named constant with the given value. The constant will be
      # undefined for the duration of the test.
      #
      # Like method stubs, the constant will be restored to its original value
      # when the example completes.
      #
      # @param constant_name [String] The fully qualified name of the constant.
      #   The current constant scoping at the point of call is not considered.
      #
      # @example
      #   hide_const("MyClass") # => MyClass is now an undefined constant
      def hide_const(constant_name)
        ConstantMutator.hide(constant_name)
      end

      # Verifies that the given object received the expected message during the
      # course of the test. On a spy objects or as null object doubles this
      # works for any method, on other objects the method must have
      # been stubbed beforehand in order for messages to be verified.
      #
      # Stubbing and verifying messages received in this way implements the
      # Test Spy pattern.
      #
      # @param method_name [Symbol] name of the method expected to have been
      #   called.
      #
      # @example
      #   invitation = double('invitation', accept: true)
      #   user.accept_invitation(invitation)
      #   expect(invitation).to have_received(:accept)
      #
      #   # You can also use most message expectations:
      #   expect(invitation).to have_received(:accept).with(mailer).once
      #
      # @note `have_received(...).with(...)` is unable to work properly when
      #   passed arguments are mutated after the spy records the received message.
      def have_received(method_name, &block)
        Matchers::HaveReceived.new(method_name, &block)
      end

      # Turns off the verifying of partial doubles for the duration of the
      # block, this is useful in situations where methods are defined at run
      # time and you wish to define stubs for them but not turn off partial
      # doubles for the entire run suite. (e.g. view specs in rspec-rails).
      def without_partial_double_verification
        original_state = Mocks.configuration.temporarily_suppress_partial_double_verification
        Mocks.configuration.temporarily_suppress_partial_double_verification = true
        yield
      ensure
        Mocks.configuration.temporarily_suppress_partial_double_verification = original_state
      end

      # @method expect
      # Used to wrap an object in preparation for setting a mock expectation
      # on it.
      #
      # @example
      #   expect(obj).to receive(:foo).with(5).and_return(:return_value)
      #
      # @note This method is usually provided by rspec-expectations. However,
      #   if you use rspec-mocks without rspec-expectations, there's a definition
      #   of it that is made available here. If you disable the `:expect` syntax
      #   this method will be undefined.

      # @method allow
      # Used to wrap an object in preparation for stubbing a method
      # on it.
      #
      # @example
      #   allow(dbl).to receive(:foo).with(5).and_return(:return_value)
      #
      # @note If you disable the `:expect` syntax this method will be undefined.

      # @method expect_any_instance_of
      # Used to wrap a class in preparation for setting a mock expectation
      # on instances of it.
      #
      # @example
      #   expect_any_instance_of(MyClass).to receive(:foo)
      #
      # @note If you disable the `:expect` syntax this method will be undefined.

      # @method allow_any_instance_of
      # Used to wrap a class in preparation for stubbing a method
      # on instances of it.
      #
      # @example
      #   allow_any_instance_of(MyClass).to receive(:foo)
      #
      # @note This is only available when you have enabled the `expect` syntax.

      # @method receive
      # Used to specify a message that you expect or allow an object
      # to receive. The object returned by `receive` supports the same
      # fluent interface that `should_receive` and `stub` have always
      # supported, allowing you to constrain the arguments or number of
      # times, and configure how the object should respond to the message.
      #
      # @example
      #   expect(obj).to receive(:hello).with("world").exactly(3).times
      #
      # @note If you disable the `:expect` syntax this method will be undefined.

      # @method receive_messages
      # Shorthand syntax used to setup message(s), and their return value(s),
      # that you expect or allow an object to receive. The method takes a hash
      # of messages and their respective return values. Unlike with `receive`,
      # you cannot apply further customizations using a block or the fluent
      # interface.
      #
      # @example
      #   allow(obj).to receive_messages(:speak => "Hello World")
      #   allow(obj).to receive_messages(:speak => "Hello", :meow => "Meow")
      #
      # @note If you disable the `:expect` syntax this method will be undefined.

      # @method receive_message_chain
      # @overload receive_message_chain(method1, method2)
      # @overload receive_message_chain("method1.method2")
      # @overload receive_message_chain(method1, method_to_value_hash)
      #
      # stubs/mocks a chain of messages on an object or test double.
      #
      # ## Warning:
      #
      # Chains can be arbitrarily long, which makes it quite painless to
      # violate the Law of Demeter in violent ways, so you should consider any
      # use of `receive_message_chain` a code smell. Even though not all code smells
      # indicate real problems (think fluent interfaces), `receive_message_chain` still
      # results in brittle examples.  For example, if you write
      # `allow(foo).to receive_message_chain(:bar, :baz => 37)` in a spec and then the
      # implementation calls `foo.baz.bar`, the stub will not work.
      #
      # @example
      #   allow(double).to receive_message_chain("foo.bar") { :baz }
      #   allow(double).to receive_message_chain(:foo, :bar => :baz)
      #   allow(double).to receive_message_chain(:foo, :bar) { :baz }
      #
      #   # Given any of ^^ these three forms ^^:
      #   double.foo.bar # => :baz
      #
      #   # Common use in Rails/ActiveRecord:
      #   allow(Article).to receive_message_chain("recent.published") { [Article.new] }
      #
      # @note If you disable the `:expect` syntax this method will be undefined.

      # @private
      def self.included(klass)
        klass.class_exec do
          # This gets mixed in so that if `RSpec::Matchers` is included in
          # `klass` later, its definition of `expect` will take precedence.
          include ExpectHost unless method_defined?(:expect)
        end
      end

      # @private
      def self.extended(object)
        # This gets extended in so that if `RSpec::Matchers` is included in
        # `klass` later, its definition of `expect` will take precedence.
        object.extend ExpectHost unless object.respond_to?(:expect)
      end

      # @private
      def self.declare_verifying_double(type, ref, *args)
        if RSpec::Mocks.configuration.verify_doubled_constant_names? &&
          !ref.defined?

          RSpec::Mocks.error_generator.raise_verifying_double_not_defined_error(ref)
        end

        RSpec::Mocks.configuration.verifying_double_callbacks.each do |block|
          block.call(ref)
        end

        declare_double(type, ref, *args)
      end

      # @private
      def self.declare_double(type, *args)
        args << {} unless Hash === args.last
        type.new(*args)
      end

      # This module exists to host the `expect` method for cases where
      # rspec-mocks is used w/o rspec-expectations.
      module ExpectHost
      end
    end
  end
end
