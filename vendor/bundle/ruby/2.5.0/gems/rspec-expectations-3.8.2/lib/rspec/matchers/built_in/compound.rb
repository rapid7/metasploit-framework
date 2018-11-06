module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Base class for `and` and `or` compound matchers.
      class Compound < BaseMatcher
        # @private
        attr_reader :matcher_1, :matcher_2, :evaluator

        def initialize(matcher_1, matcher_2)
          @matcher_1 = matcher_1
          @matcher_2 = matcher_2
        end

        # @private
        def does_not_match?(_actual)
          raise NotImplementedError, "`expect(...).not_to matcher.#{conjunction} matcher` " \
            "is not supported, since it creates a bit of an ambiguity. Instead, define negated versions " \
            "of whatever matchers you wish to negate with `RSpec::Matchers.define_negated_matcher` and " \
            "use `expect(...).to matcher.#{conjunction} matcher`."
        end

        # @api private
        # @return [String]
        def description
          "#{matcher_1.description} #{conjunction} #{matcher_2.description}"
        end

        def supports_block_expectations?
          matcher_supports_block_expectations?(matcher_1) &&
          matcher_supports_block_expectations?(matcher_2)
        end

        def expects_call_stack_jump?
          NestedEvaluator.matcher_expects_call_stack_jump?(matcher_1) ||
          NestedEvaluator.matcher_expects_call_stack_jump?(matcher_2)
        end

        # @api private
        # @return [Boolean]
        def diffable?
          matcher_is_diffable?(matcher_1) || matcher_is_diffable?(matcher_2)
        end

        # @api private
        # @return [RSpec::Matchers::ExpectedsForMultipleDiffs]
        def expected
          return nil unless evaluator
          ::RSpec::Matchers::ExpectedsForMultipleDiffs.for_many_matchers(diffable_matcher_list)
        end

      protected

        def diffable_matcher_list
          list = []
          list.concat(diffable_matcher_list_for(matcher_1)) unless matcher_1_matches?
          list.concat(diffable_matcher_list_for(matcher_2)) unless matcher_2_matches?
          list
        end

      private

        def initialize_copy(other)
          @matcher_1 = @matcher_1.clone
          @matcher_2 = @matcher_2.clone
          super
        end

        def match(_expected, actual)
          evaluator_klass = if supports_block_expectations? && Proc === actual
                              NestedEvaluator
                            else
                              SequentialEvaluator
                            end

          @evaluator = evaluator_klass.new(actual, matcher_1, matcher_2)
        end

        def indent_multiline_message(message)
          message.lines.map do |line|
            line =~ /\S/ ? '   ' + line : line
          end.join
        end

        def compound_failure_message
          "#{indent_multiline_message(matcher_1.failure_message.sub(/\n+\z/, ''))}" \
          "\n\n...#{conjunction}:" \
          "\n\n#{indent_multiline_message(matcher_2.failure_message.sub(/\A\n+/, ''))}"
        end

        def matcher_1_matches?
          evaluator.matcher_matches?(matcher_1)
        end

        def matcher_2_matches?
          evaluator.matcher_matches?(matcher_2)
        end

        def matcher_supports_block_expectations?(matcher)
          matcher.supports_block_expectations?
        rescue NoMethodError
          false
        end

        def matcher_is_diffable?(matcher)
          matcher.diffable?
        rescue NoMethodError
          false
        end

        def diffable_matcher_list_for(matcher)
          return [] unless matcher_is_diffable?(matcher)
          return matcher.diffable_matcher_list if Compound === matcher
          [matcher]
        end

        # For value expectations, we can evaluate the matchers sequentially.
        class SequentialEvaluator
          def initialize(actual, *)
            @actual = actual
          end

          def matcher_matches?(matcher)
            matcher.matches?(@actual)
          end
        end

        # Normally, we evaluate the matching sequentially. For an expression like
        # `expect(x).to foo.and bar`, this becomes:
        #
        #   expect(x).to foo
        #   expect(x).to bar
        #
        # For block expectations, we need to nest them instead, so that
        # `expect { x }.to foo.and bar` becomes:
        #
        #   expect {
        #     expect { x }.to foo
        #   }.to bar
        #
        # This is necessary so that the `expect` block is only executed once.
        class NestedEvaluator
          def initialize(actual, matcher_1, matcher_2)
            @actual        = actual
            @matcher_1     = matcher_1
            @matcher_2     = matcher_2
            @match_results = {}

            inner, outer = order_block_matchers

            @match_results[outer] = outer.matches?(Proc.new do |*args|
              @match_results[inner] = inner.matches?(inner_matcher_block(args))
            end)
          end

          def matcher_matches?(matcher)
            @match_results.fetch(matcher)
          end

        private

          # Some block matchers (such as `yield_xyz`) pass args to the `expect` block.
          # When such a matcher is used as the outer matcher, we need to forward the
          # the args on to the `expect` block.
          def inner_matcher_block(outer_args)
            return @actual if outer_args.empty?

            Proc.new do |*inner_args|
              unless inner_args.empty?
                raise ArgumentError, "(#{@matcher_1.description}) and " \
                  "(#{@matcher_2.description}) cannot be combined in a compound expectation " \
                  "since both matchers pass arguments to the block."
              end

              @actual.call(*outer_args)
            end
          end

          # For a matcher like `raise_error` or `throw_symbol`, where the block will jump
          # up the call stack, we need to order things so that it is the inner matcher.
          # For example, we need it to be this:
          #
          #   expect {
          #     expect {
          #       x += 1
          #       raise "boom"
          #     }.to raise_error("boom")
          #   }.to change { x }.by(1)
          #
          # ...rather than:
          #
          #   expect {
          #     expect {
          #       x += 1
          #       raise "boom"
          #     }.to change { x }.by(1)
          #   }.to raise_error("boom")
          #
          # In the latter case, the after-block logic in the `change` matcher would never
          # get executed because the `raise "boom"` line would jump to the `rescue` in the
          # `raise_error` logic, so only the former case will work properly.
          #
          # This method figures out which matcher should be the inner matcher and which
          # should be the outer matcher.
          def order_block_matchers
            return @matcher_1, @matcher_2 unless self.class.matcher_expects_call_stack_jump?(@matcher_2)
            return @matcher_2, @matcher_1 unless self.class.matcher_expects_call_stack_jump?(@matcher_1)

            raise ArgumentError, "(#{@matcher_1.description}) and " \
              "(#{@matcher_2.description}) cannot be combined in a compound expectation " \
              "because they both expect a call stack jump."
          end

          def self.matcher_expects_call_stack_jump?(matcher)
            matcher.expects_call_stack_jump?
          rescue NoMethodError
            false
          end
        end

        # @api public
        # Matcher used to represent a compound `and` expectation.
        class And < self
          # @api private
          # @return [String]
          def failure_message
            if matcher_1_matches?
              matcher_2.failure_message
            elsif matcher_2_matches?
              matcher_1.failure_message
            else
              compound_failure_message
            end
          end

        private

          def match(*)
            super
            matcher_1_matches? && matcher_2_matches?
          end

          def conjunction
            "and"
          end
        end

        # @api public
        # Matcher used to represent a compound `or` expectation.
        class Or < self
          # @api private
          # @return [String]
          def failure_message
            compound_failure_message
          end

        private

          def match(*)
            super
            matcher_1_matches? || matcher_2_matches?
          end

          def conjunction
            "or"
          end
        end
      end
    end
  end
end
