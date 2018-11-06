module RSpec
  module Mocks
    # A message expectation that only allows concrete return values to be set
    # for a message. While this same effect can be achieved using a standard
    # MessageExpectation, this version is much faster and so can be used as an
    # optimization.
    #
    # @private
    class SimpleMessageExpectation
      def initialize(message, response, error_generator, backtrace_line=nil)
        @message, @response, @error_generator, @backtrace_line = message.to_sym, response, error_generator, backtrace_line
        @received = false
      end

      def invoke(*_)
        @received = true
        @response
      end

      def matches?(message, *_)
        @message == message.to_sym
      end

      def called_max_times?
        false
      end

      def verify_messages_received
        return if @received
        @error_generator.raise_expectation_error(
          @message, 1, ArgumentListMatcher::MATCH_ALL, 0, nil, [], @backtrace_line
        )
      end

      def unadvise(_)
      end
    end

    # Represents an individual method stub or message expectation. The methods
    # defined here can be used to configure how it behaves. The methods return
    # `self` so that they can be chained together to form a fluent interface.
    class MessageExpectation
      # @!group Configuring Responses

      # @overload and_return(value)
      # @overload and_return(first_value, second_value)
      #
      # Tells the object to return a value when it receives the message.  Given
      # more than one value, the first value is returned the first time the
      # message is received, the second value is returned the next time, etc,
      # etc.
      #
      # If the message is received more times than there are values, the last
      # value is received for every subsequent call.
      #
      # @return [nil] No further chaining is supported after this.
      # @example
      #   allow(counter).to receive(:count).and_return(1)
      #   counter.count # => 1
      #   counter.count # => 1
      #
      #   allow(counter).to receive(:count).and_return(1,2,3)
      #   counter.count # => 1
      #   counter.count # => 2
      #   counter.count # => 3
      #   counter.count # => 3
      #   counter.count # => 3
      #   # etc
      def and_return(first_value, *values)
        raise_already_invoked_error_if_necessary(__method__)
        if negative?
          raise "`and_return` is not supported with negative message expectations"
        end

        if block_given?
          raise ArgumentError, "Implementation blocks aren't supported with `and_return`"
        end

        values.unshift(first_value)
        @expected_received_count = [@expected_received_count, values.size].max unless ignoring_args? || (@expected_received_count == 0 && @at_least)
        self.terminal_implementation_action = AndReturnImplementation.new(values)

        nil
      end

      # Tells the object to delegate to the original unmodified method
      # when it receives the message.
      #
      # @note This is only available on partial doubles.
      #
      # @return [nil] No further chaining is supported after this.
      # @example
      #   expect(counter).to receive(:increment).and_call_original
      #   original_count = counter.count
      #   counter.increment
      #   expect(counter.count).to eq(original_count + 1)
      def and_call_original
        wrap_original(__method__) do |original, *args, &block|
          original.call(*args, &block)
        end
      end

      # Decorates the stubbed method with the supplied block. The original
      # unmodified method is passed to the block along with any method call
      # arguments so you can delegate to it, whilst still being able to
      # change what args are passed to it and/or change the return value.
      #
      # @note This is only available on partial doubles.
      #
      # @return [nil] No further chaining is supported after this.
      # @example
      #   expect(api).to receive(:large_list).and_wrap_original do |original_method, *args, &block|
      #     original_method.call(*args, &block).first(10)
      #   end
      def and_wrap_original(&block)
        wrap_original(__method__, &block)
      end

      # @overload and_raise
      # @overload and_raise(ExceptionClass)
      # @overload and_raise(ExceptionClass, message)
      # @overload and_raise(exception_instance)
      #
      # Tells the object to raise an exception when the message is received.
      #
      # @return [nil] No further chaining is supported after this.
      # @note
      #   When you pass an exception class, the MessageExpectation will raise
      #   an instance of it, creating it with `exception` and passing `message`
      #   if specified.  If the exception class initializer requires more than
      #   one parameters, you must pass in an instance and not the class,
      #   otherwise this method will raise an ArgumentError exception.
      #
      # @example
      #   allow(car).to receive(:go).and_raise
      #   allow(car).to receive(:go).and_raise(OutOfGas)
      #   allow(car).to receive(:go).and_raise(OutOfGas, "At least 2 oz of gas needed to drive")
      #   allow(car).to receive(:go).and_raise(OutOfGas.new(2, :oz))
      def and_raise(*args)
        raise_already_invoked_error_if_necessary(__method__)
        self.terminal_implementation_action = Proc.new { raise(*args) }
        nil
      end

      # @overload and_throw(symbol)
      # @overload and_throw(symbol, object)
      #
      # Tells the object to throw a symbol (with the object if that form is
      # used) when the message is received.
      #
      # @return [nil] No further chaining is supported after this.
      # @example
      #   allow(car).to receive(:go).and_throw(:out_of_gas)
      #   allow(car).to receive(:go).and_throw(:out_of_gas, :level => 0.1)
      def and_throw(*args)
        raise_already_invoked_error_if_necessary(__method__)
        self.terminal_implementation_action = Proc.new { throw(*args) }
        nil
      end

      # Tells the object to yield one or more args to a block when the message
      # is received.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   stream.stub(:open).and_yield(StringIO.new)
      def and_yield(*args, &block)
        raise_already_invoked_error_if_necessary(__method__)
        yield @eval_context = Object.new if block

        # Initialize args to yield now that it's being used, see also: comment
        # in constructor.
        @args_to_yield ||= []

        @args_to_yield << args
        self.initial_implementation_action = AndYieldImplementation.new(@args_to_yield, @eval_context, @error_generator)
        self
      end
      # @!endgroup

      # @!group Constraining Receive Counts

      # Constrain a message expectation to be received a specific number of
      # times.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(dealer).to receive(:deal_card).exactly(10).times
      def exactly(n, &block)
        raise_already_invoked_error_if_necessary(__method__)
        self.inner_implementation_action = block
        set_expected_received_count :exactly, n
        self
      end

      # Constrain a message expectation to be received at least a specific
      # number of times.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(dealer).to receive(:deal_card).at_least(9).times
      def at_least(n, &block)
        raise_already_invoked_error_if_necessary(__method__)
        set_expected_received_count :at_least, n

        if n == 0
          raise "at_least(0) has been removed, use allow(...).to receive(:message) instead"
        end

        self.inner_implementation_action = block

        self
      end

      # Constrain a message expectation to be received at most a specific
      # number of times.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(dealer).to receive(:deal_card).at_most(10).times
      def at_most(n, &block)
        raise_already_invoked_error_if_necessary(__method__)
        self.inner_implementation_action = block
        set_expected_received_count :at_most, n
        self
      end

      # Syntactic sugar for `exactly`, `at_least` and `at_most`
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(dealer).to receive(:deal_card).exactly(10).times
      #   expect(dealer).to receive(:deal_card).at_least(10).times
      #   expect(dealer).to receive(:deal_card).at_most(10).times
      def times(&block)
        self.inner_implementation_action = block
        self
      end

      # Expect a message not to be received at all.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(car).to receive(:stop).never
      def never
        error_generator.raise_double_negation_error("expect(obj)") if negative?
        @expected_received_count = 0
        self
      end

      # Expect a message to be received exactly one time.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(car).to receive(:go).once
      def once(&block)
        self.inner_implementation_action = block
        set_expected_received_count :exactly, 1
        self
      end

      # Expect a message to be received exactly two times.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(car).to receive(:go).twice
      def twice(&block)
        self.inner_implementation_action = block
        set_expected_received_count :exactly, 2
        self
      end

      # Expect a message to be received exactly three times.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(car).to receive(:go).thrice
      def thrice(&block)
        self.inner_implementation_action = block
        set_expected_received_count :exactly, 3
        self
      end
      # @!endgroup

      # @!group Other Constraints

      # Constrains a stub or message expectation to invocations with specific
      # arguments.
      #
      # With a stub, if the message might be received with other args as well,
      # you should stub a default value first, and then stub or mock the same
      # message using `with` to constrain to specific arguments.
      #
      # A message expectation will fail if the message is received with different
      # arguments.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   allow(cart).to receive(:add) { :failure }
      #   allow(cart).to receive(:add).with(Book.new(:isbn => 1934356379)) { :success }
      #   cart.add(Book.new(:isbn => 1234567890))
      #   # => :failure
      #   cart.add(Book.new(:isbn => 1934356379))
      #   # => :success
      #
      #   expect(cart).to receive(:add).with(Book.new(:isbn => 1934356379)) { :success }
      #   cart.add(Book.new(:isbn => 1234567890))
      #   # => failed expectation
      #   cart.add(Book.new(:isbn => 1934356379))
      #   # => passes
      def with(*args, &block)
        raise_already_invoked_error_if_necessary(__method__)
        if args.empty?
          raise ArgumentError,
                "`with` must have at least one argument. Use `no_args` matcher to set the expectation of receiving no arguments."
        end

        self.inner_implementation_action = block
        @argument_list_matcher = ArgumentListMatcher.new(*args)
        self
      end

      # Expect messages to be received in a specific order.
      #
      # @return [MessageExpectation] self, to support further chaining.
      # @example
      #   expect(api).to receive(:prepare).ordered
      #   expect(api).to receive(:run).ordered
      #   expect(api).to receive(:finish).ordered
      def ordered(&block)
        if type == :stub
          RSpec.warning(
            "`allow(...).to receive(..).ordered` is not supported and will " \
            "have no effect, use `and_return(*ordered_values)` instead."
          )
        end

        self.inner_implementation_action = block
        additional_expected_calls.times do
          @order_group.register(self)
        end
        @ordered = true
        self
      end

      # @return [String] a nice representation of the message expectation
      def to_s
        args_description = error_generator.method_call_args_description(@argument_list_matcher.expected_args, "", "") { true }
        args_description = "(#{args_description})" unless args_description.start_with?("(")
        "#<#{self.class} #{error_generator.intro}.#{message}#{args_description}>"
      end
      alias inspect to_s

      # @private
      # Contains the parts of `MessageExpectation` that aren't part of
      # rspec-mocks' public API. The class is very big and could really use
      # some collaborators it delegates to for this stuff but for now this was
      # the simplest way to split the public from private stuff to make it
      # easier to publish the docs for the APIs we want published.
      module ImplementationDetails
        attr_accessor :error_generator, :implementation
        attr_reader :message
        attr_reader :orig_object
        attr_writer :expected_received_count, :expected_from, :argument_list_matcher
        protected :expected_received_count=, :expected_from=, :error_generator, :error_generator=, :implementation=

        # @private
        attr_reader :type

        # rubocop:disable Metrics/ParameterLists
        def initialize(error_generator, expectation_ordering, expected_from, method_double,
                       type=:expectation, opts={}, &implementation_block)
          @type = type
          @error_generator = error_generator
          @error_generator.opts = opts
          @expected_from = expected_from
          @method_double = method_double
          @orig_object = @method_double.object
          @message = @method_double.method_name
          @actual_received_count = 0
          @expected_received_count = type == :expectation ? 1 : :any
          @argument_list_matcher = ArgumentListMatcher::MATCH_ALL
          @order_group = expectation_ordering
          @order_group.register(self) unless type == :stub
          @expectation_type = type
          @ordered = false
          @at_least = @at_most = @exactly = nil

          # Initialized to nil so that we don't allocate an array for every
          # mock or stub. See also comment in `and_yield`.
          @args_to_yield = nil
          @eval_context = nil
          @yield_receiver_to_implementation_block = false

          @implementation = Implementation.new
          self.inner_implementation_action = implementation_block
        end
        # rubocop:enable Metrics/ParameterLists

        def expected_args
          @argument_list_matcher.expected_args
        end

        def and_yield_receiver_to_implementation
          @yield_receiver_to_implementation_block = true
          self
        end

        def yield_receiver_to_implementation_block?
          @yield_receiver_to_implementation_block
        end

        def matches?(message, *args)
          @message == message && @argument_list_matcher.args_match?(*args)
        end

        def safe_invoke(parent_stub, *args, &block)
          invoke_incrementing_actual_calls_by(1, false, parent_stub, *args, &block)
        end

        def invoke(parent_stub, *args, &block)
          invoke_incrementing_actual_calls_by(1, true, parent_stub, *args, &block)
        end

        def invoke_without_incrementing_received_count(parent_stub, *args, &block)
          invoke_incrementing_actual_calls_by(0, true, parent_stub, *args, &block)
        end

        def negative?
          @expected_received_count == 0 && !@at_least
        end

        def called_max_times?
          @expected_received_count != :any &&
            !@at_least &&
            @expected_received_count > 0 &&
            @actual_received_count >= @expected_received_count
        end

        def matches_name_but_not_args(message, *args)
          @message == message && !@argument_list_matcher.args_match?(*args)
        end

        def verify_messages_received
          return if expected_messages_received?
          generate_error
        end

        def expected_messages_received?
          ignoring_args? || matches_exact_count? || matches_at_least_count? || matches_at_most_count?
        end

        def ensure_expected_ordering_received!
          @order_group.verify_invocation_order(self) if @ordered
          true
        end

        def ignoring_args?
          @expected_received_count == :any
        end

        def matches_at_least_count?
          @at_least && @actual_received_count >= @expected_received_count
        end

        def matches_at_most_count?
          @at_most && @actual_received_count <= @expected_received_count
        end

        def matches_exact_count?
          @expected_received_count == @actual_received_count
        end

        def similar_messages
          @similar_messages ||= []
        end

        def advise(*args)
          similar_messages << args
        end

        def unadvise(args)
          similar_messages.delete_if { |message| args.include?(message) }
        end

        def generate_error
          if similar_messages.empty?
            @error_generator.raise_expectation_error(
              @message, @expected_received_count, @argument_list_matcher,
              @actual_received_count, expectation_count_type, expected_args,
              @expected_from, exception_source_id
            )
          else
            @error_generator.raise_similar_message_args_error(
              self, @similar_messages, @expected_from
            )
          end
        end

        def raise_unexpected_message_args_error(args_for_multiple_calls)
          @error_generator.raise_unexpected_message_args_error(self, args_for_multiple_calls, exception_source_id)
        end

        def expectation_count_type
          return :at_least if @at_least
          return :at_most if @at_most
          nil
        end

        def description_for(verb)
          @error_generator.describe_expectation(
            verb, @message, @expected_received_count,
            @actual_received_count, expected_args
          )
        end

        def raise_out_of_order_error
          @error_generator.raise_out_of_order_error @message
        end

        def additional_expected_calls
          return 0 if @expectation_type == :stub || !@exactly
          @expected_received_count - 1
        end

        def ordered?
          @ordered
        end

        def negative_expectation_for?(message)
          @message == message && negative?
        end

        def actual_received_count_matters?
          @at_least || @at_most || @exactly
        end

        def increase_actual_received_count!
          @actual_received_count += 1
        end

      private

        def exception_source_id
          @exception_source_id ||= "#{self.class.name} #{__id__}"
        end

        def invoke_incrementing_actual_calls_by(increment, allowed_to_fail, parent_stub, *args, &block)
          args.unshift(orig_object) if yield_receiver_to_implementation_block?

          if negative? || (allowed_to_fail && (@exactly || @at_most) && (@actual_received_count == @expected_received_count))
            # args are the args we actually received, @argument_list_matcher is the
            # list of args we were expecting
            @error_generator.raise_expectation_error(
              @message, @expected_received_count,
              @argument_list_matcher,
              @actual_received_count + increment,
              expectation_count_type, args, nil, exception_source_id
            )
          end

          @order_group.handle_order_constraint self

          if implementation.present?
            implementation.call(*args, &block)
          elsif parent_stub
            parent_stub.invoke(nil, *args, &block)
          end
        ensure
          @actual_received_count += increment
        end

        def has_been_invoked?
          @actual_received_count > 0
        end

        def raise_already_invoked_error_if_necessary(calling_customization)
          return unless has_been_invoked?

          error_generator.raise_already_invoked_error(message, calling_customization)
        end

        def set_expected_received_count(relativity, n)
          raise "`count` is not supported with negative message expectations" if negative?
          @at_least = (relativity == :at_least)
          @at_most  = (relativity == :at_most)
          @exactly  = (relativity == :exactly)
          @expected_received_count = case n
                                     when Numeric then n
                                     when :once   then 1
                                     when :twice  then 2
                                     when :thrice then 3
                                     end
        end

        def initial_implementation_action=(action)
          implementation.initial_action = action
        end

        def inner_implementation_action=(action)
          return unless action
          warn_about_stub_override if implementation.inner_action
          implementation.inner_action = action
        end

        def terminal_implementation_action=(action)
          implementation.terminal_action = action
        end

        def warn_about_stub_override
          RSpec.warning(
            "You're overriding a previous stub implementation of `#{@message}`. " \
            "Called from #{CallerFilter.first_non_rspec_line}."
          )
        end

        def wrap_original(method_name, &block)
          if RSpec::Mocks::TestDouble === @method_double.object
            @error_generator.raise_only_valid_on_a_partial_double(method_name)
          else
            warn_about_stub_override if implementation.inner_action
            @implementation = AndWrapOriginalImplementation.new(@method_double.original_implementation_callable, block)
            @yield_receiver_to_implementation_block = false
          end

          nil
        end
      end

      include ImplementationDetails
    end

    # Handles the implementation of an `and_yield` declaration.
    # @private
    class AndYieldImplementation
      def initialize(args_to_yield, eval_context, error_generator)
        @args_to_yield = args_to_yield
        @eval_context = eval_context
        @error_generator = error_generator
      end

      def call(*_args_to_ignore, &block)
        return if @args_to_yield.empty? && @eval_context.nil?

        @error_generator.raise_missing_block_error @args_to_yield unless block
        value = nil
        block_signature = Support::BlockSignature.new(block)

        @args_to_yield.each do |args|
          unless Support::StrictSignatureVerifier.new(block_signature, args).valid?
            @error_generator.raise_wrong_arity_error(args, block_signature)
          end

          value = @eval_context ? @eval_context.instance_exec(*args, &block) : yield(*args)
        end
        value
      end
    end

    # Handles the implementation of an `and_return` implementation.
    # @private
    class AndReturnImplementation
      def initialize(values_to_return)
        @values_to_return = values_to_return
      end

      def call(*_args_to_ignore, &_block)
        if @values_to_return.size > 1
          @values_to_return.shift
        else
          @values_to_return.first
        end
      end
    end

    # Represents a configured implementation. Takes into account
    # any number of sub-implementations.
    # @private
    class Implementation
      attr_accessor :initial_action, :inner_action, :terminal_action

      def call(*args, &block)
        actions.map do |action|
          action.call(*args, &block)
        end.last
      end

      def present?
        actions.any?
      end

    private

      def actions
        [initial_action, inner_action, terminal_action].compact
      end
    end

    # Represents an `and_call_original` implementation.
    # @private
    class AndWrapOriginalImplementation
      def initialize(method, block)
        @method = method
        @block = block
      end

      CannotModifyFurtherError = Class.new(StandardError)

      def initial_action=(_value)
        raise cannot_modify_further_error
      end

      def inner_action=(_value)
        raise cannot_modify_further_error
      end

      def terminal_action=(_value)
        raise cannot_modify_further_error
      end

      def present?
        true
      end

      def inner_action
        true
      end

      def call(*args, &block)
        @block.call(@method, *args, &block)
      end

    private

      def cannot_modify_further_error
        CannotModifyFurtherError.new "This method has already been configured " \
          "to call the original implementation, and cannot be modified further."
      end
    end
  end
end
