RSpec::Support.require_rspec_support 'method_signature_verifier'

module RSpec
  module Matchers
    module BuiltIn
      # @private
      # Object that is yielded to `expect` when one of the
      # yield matchers is used. Provides information about
      # the yield behavior of the object-under-test.
      class YieldProbe
        def self.probe(block, &callback)
          probe = new(block, &callback)
          return probe unless probe.has_block?
          probe.probe
        end

        attr_accessor :num_yields, :yielded_args

        def initialize(block, &callback)
          @block = block
          @callback = callback || Proc.new {}
          @used = false
          self.num_yields = 0
          self.yielded_args = []
        end

        def has_block?
          Proc === @block
        end

        def probe
          assert_valid_expect_block!
          @block.call(self)
          assert_used!
          self
        end

        def to_proc
          @used = true

          probe = self
          callback = @callback
          Proc.new do |*args|
            probe.num_yields += 1
            probe.yielded_args << args
            callback.call(*args)
            nil # to indicate the block does not return a meaningful value
          end
        end

        def single_yield_args
          yielded_args.first
        end

        def yielded_once?(matcher_name)
          case num_yields
          when 1 then true
          when 0 then false
          else
            raise "The #{matcher_name} matcher is not designed to be used with a " \
                  'method that yields multiple times. Use the yield_successive_args ' \
                  'matcher for that case.'
          end
        end

        def assert_used!
          return if @used
          raise 'You must pass the argument yielded to your expect block on ' \
                'to the method-under-test as a block. It acts as a probe that ' \
                'allows the matcher to detect whether or not the method-under-test ' \
                'yields, and, if so, how many times, and what the yielded arguments ' \
                'are.'
        end

        if RUBY_VERSION.to_f > 1.8
          def assert_valid_expect_block!
            block_signature = RSpec::Support::BlockSignature.new(@block)
            return if RSpec::Support::StrictSignatureVerifier.new(block_signature, [self]).valid?
            raise 'Your expect block must accept an argument to be used with this ' \
                  'matcher. Pass the argument as a block on to the method you are testing.'
          end
        else
          # :nocov:
          # On 1.8.7, `lambda { }.arity` and `lambda { |*a| }.arity` both return -1,
          # so we can't distinguish between accepting no args and an arg splat.
          # It's OK to skip, this, though; it just provides a nice error message
          # when the user forgets to accept an arg in their block. They'll still get
          # the `assert_used!` error message from above, which is sufficient.
          def assert_valid_expect_block!
            # nothing to do
          end
          # :nocov:
        end
      end

      # @api private
      # Provides the implementation for `yield_control`.
      # Not intended to be instantiated directly.
      class YieldControl < BaseMatcher
        def initialize
          at_least(:once)
        end

        # @api public
        # Specifies that the method is expected to yield once.
        def once
          exactly(1)
          self
        end

        # @api public
        # Specifies that the method is expected to yield twice.
        def twice
          exactly(2)
          self
        end

        # @api public
        # Specifies that the method is expected to yield thrice.
        def thrice
          exactly(3)
          self
        end

        # @api public
        # Specifies that the method is expected to yield the given number of times.
        def exactly(number)
          set_expected_yields_count(:==, number)
          self
        end

        # @api public
        # Specifies the maximum number of times the method is expected to yield
        def at_most(number)
          set_expected_yields_count(:<=, number)
          self
        end

        # @api public
        # Specifies the minimum number of times the method is expected to yield
        def at_least(number)
          set_expected_yields_count(:>=, number)
          self
        end

        # @api public
        # No-op. Provides syntactic sugar.
        def times
          self
        end

        # @private
        def matches?(block)
          @probe = YieldProbe.probe(block)
          return false unless @probe.has_block?

          @probe.num_yields.__send__(@expectation_type, @expected_yields_count)
        end

        # @private
        def does_not_match?(block)
          !matches?(block) && @probe.has_block?
        end

        # @api private
        # @return [String]
        def failure_message
          'expected given block to yield control' + failure_reason
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          'expected given block not to yield control' + failure_reason
        end

        # @private
        def supports_block_expectations?
          true
        end

      private

        def set_expected_yields_count(relativity, n)
          @expectation_type = relativity
          @expected_yields_count = case n
                                   when Numeric then n
                                   when :once then 1
                                   when :twice then 2
                                   when :thrice then 3
                                   end
        end

        def failure_reason
          return ' but was not a block' unless @probe.has_block?
          return '' unless @expected_yields_count
          " #{human_readable_expectation_type}#{human_readable_count(@expected_yields_count)}" \
          " but yielded #{human_readable_count(@probe.num_yields)}"
        end

        def human_readable_expectation_type
          case @expectation_type
          when :<= then 'at most '
          when :>= then 'at least '
          else ''
          end
        end

        def human_readable_count(count)
          case count
          when 1 then 'once'
          when 2 then 'twice'
          else "#{count} times"
          end
        end
      end

      # @api private
      # Provides the implementation for `yield_with_no_args`.
      # Not intended to be instantiated directly.
      class YieldWithNoArgs < BaseMatcher
        # @private
        def matches?(block)
          @probe = YieldProbe.probe(block)
          return false unless @probe.has_block?
          @probe.yielded_once?(:yield_with_no_args) && @probe.single_yield_args.empty?
        end

        # @private
        def does_not_match?(block)
          !matches?(block) && @probe.has_block?
        end

        # @private
        def failure_message
          "expected given block to yield with no arguments, but #{positive_failure_reason}"
        end

        # @private
        def failure_message_when_negated
          "expected given block not to yield with no arguments, but #{negative_failure_reason}"
        end

        # @private
        def supports_block_expectations?
          true
        end

      private

        def positive_failure_reason
          return 'was not a block' unless @probe.has_block?
          return 'did not yield' if @probe.num_yields.zero?
          "yielded with arguments: #{description_of @probe.single_yield_args}"
        end

        def negative_failure_reason
          return 'was not a block' unless @probe.has_block?
          'did'
        end
      end

      # @api private
      # Provides the implementation for `yield_with_args`.
      # Not intended to be instantiated directly.
      class YieldWithArgs < BaseMatcher
        def initialize(*args)
          @expected = args
        end

        # @private
        def matches?(block)
          @args_matched_when_yielded = true
          @probe = YieldProbe.new(block) do
            @actual = @probe.single_yield_args
            @actual_formatted = actual_formatted
            @args_matched_when_yielded &&= args_currently_match?
          end
          return false unless @probe.has_block?
          @probe.probe
          @probe.yielded_once?(:yield_with_args) && @args_matched_when_yielded
        end

        # @private
        def does_not_match?(block)
          !matches?(block) && @probe.has_block?
        end

        # @private
        def failure_message
          "expected given block to yield with arguments, but #{positive_failure_reason}"
        end

        # @private
        def failure_message_when_negated
          "expected given block not to yield with arguments, but #{negative_failure_reason}"
        end

        # @private
        def description
          desc = 'yield with args'
          desc = "#{desc}(#{expected_arg_description})" unless @expected.empty?
          desc
        end

        # @private
        def supports_block_expectations?
          true
        end

      private

        def positive_failure_reason
          return 'was not a block' unless @probe.has_block?
          return 'did not yield' if @probe.num_yields.zero?
          @positive_args_failure
        end

        def expected_arg_description
          @expected.map { |e| description_of e }.join(', ')
        end

        def negative_failure_reason
          if !@probe.has_block?
            'was not a block'
          elsif @args_matched_when_yielded && !@expected.empty?
            'yielded with expected arguments' \
              "\nexpected not: #{surface_descriptions_in(@expected).inspect}" \
              "\n         got: #{@actual_formatted}"
          else
            'did'
          end
        end

        def args_currently_match?
          if @expected.empty? # expect {...}.to yield_with_args
            @positive_args_failure = 'yielded with no arguments' if @actual.empty?
            return !@actual.empty?
          end

          unless (match = all_args_match?)
            @positive_args_failure = 'yielded with unexpected arguments' \
              "\nexpected: #{surface_descriptions_in(@expected).inspect}" \
              "\n     got: #{@actual_formatted}"
          end

          match
        end

        def all_args_match?
          values_match?(@expected, @actual)
        end
      end

      # @api private
      # Provides the implementation for `yield_successive_args`.
      # Not intended to be instantiated directly.
      class YieldSuccessiveArgs < BaseMatcher
        def initialize(*args)
          @expected = args
        end

        # @private
        def matches?(block)
          @actual_formatted = []
          @actual = []
          args_matched_when_yielded = true
          yield_count = 0

          @probe = YieldProbe.probe(block) do |*arg_array|
            arg_or_args = arg_array.size == 1 ? arg_array.first : arg_array
            @actual_formatted << RSpec::Support::ObjectFormatter.format(arg_or_args)
            @actual << arg_or_args
            args_matched_when_yielded &&= values_match?(@expected[yield_count], arg_or_args)
            yield_count += 1
          end

          return false unless @probe.has_block?
          args_matched_when_yielded && yield_count == @expected.length
        end

        def does_not_match?(block)
          !matches?(block) && @probe.has_block?
        end

        # @private
        def failure_message
          'expected given block to yield successively with arguments, ' \
          "but #{positive_failure_reason}"
        end

        # @private
        def failure_message_when_negated
          'expected given block not to yield successively with arguments, ' \
          "but #{negative_failure_reason}"
        end

        # @private
        def description
          "yield successive args(#{expected_arg_description})"
        end

        # @private
        def supports_block_expectations?
          true
        end

      private

        def expected_arg_description
          @expected.map { |e| description_of e }.join(', ')
        end

        def positive_failure_reason
          return 'was not a block' unless @probe.has_block?

          'yielded with unexpected arguments' \
          "\nexpected: #{surface_descriptions_in(@expected).inspect}" \
          "\n     got: [#{@actual_formatted.join(", ")}]"
        end

        def negative_failure_reason
          return 'was not a block' unless @probe.has_block?

          'yielded with expected arguments' \
          "\nexpected not: #{surface_descriptions_in(@expected).inspect}" \
          "\n         got: [#{@actual_formatted.join(", ")}]"
        end
      end
    end
  end
end
