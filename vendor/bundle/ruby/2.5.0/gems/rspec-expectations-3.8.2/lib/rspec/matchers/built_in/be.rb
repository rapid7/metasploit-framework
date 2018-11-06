module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `be_truthy`.
      # Not intended to be instantiated directly.
      class BeTruthy < BaseMatcher
        # @api private
        # @return [String]
        def failure_message
          "expected: truthy value\n     got: #{actual_formatted}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected: falsey value\n     got: #{actual_formatted}"
        end

      private

        def match(_, actual)
          !!actual
        end
      end

      # @api private
      # Provides the implementation for `be_falsey`.
      # Not intended to be instantiated directly.
      class BeFalsey < BaseMatcher
        # @api private
        # @return [String]
        def failure_message
          "expected: falsey value\n     got: #{actual_formatted}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected: truthy value\n     got: #{actual_formatted}"
        end

      private

        def match(_, actual)
          !actual
        end
      end

      # @api private
      # Provides the implementation for `be_nil`.
      # Not intended to be instantiated directly.
      class BeNil < BaseMatcher
        # @api private
        # @return [String]
        def failure_message
          "expected: nil\n     got: #{actual_formatted}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected: not nil\n     got: nil"
        end

      private

        def match(_, actual)
          actual.nil?
        end
      end

      # @private
      module BeHelpers
      private

        def args_to_s
          @args.empty? ? "" : parenthesize(inspected_args.join(', '))
        end

        def parenthesize(string)
          "(#{string})"
        end

        def inspected_args
          @args.map { |a| RSpec::Support::ObjectFormatter.format(a) }
        end

        def expected_to_sentence
          EnglishPhrasing.split_words(@expected)
        end

        def args_to_sentence
          EnglishPhrasing.list(@args)
        end
      end

      # @api private
      # Provides the implementation for `be`.
      # Not intended to be instantiated directly.
      class Be < BaseMatcher
        include BeHelpers

        def initialize(*args)
          @args = args
        end

        # @api private
        # @return [String]
        def failure_message
          "expected #{actual_formatted} to evaluate to true"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected #{actual_formatted} to evaluate to false"
        end

        [:==, :<, :<=, :>=, :>, :===, :=~].each do |operator|
          define_method operator do |operand|
            BeComparedTo.new(operand, operator)
          end
        end

      private

        def match(_, actual)
          !!actual
        end
      end

      # @api private
      # Provides the implementation of `be <operator> value`.
      # Not intended to be instantiated directly.
      class BeComparedTo < BaseMatcher
        include BeHelpers

        def initialize(operand, operator)
          @expected = operand
          @operator = operator
          @args = []
        end

        def matches?(actual)
          @actual = actual
          @actual.__send__ @operator, @expected
        rescue ArgumentError, NoMethodError
          false
        end

        # @api private
        # @return [String]
        def failure_message
          "expected: #{@operator} #{expected_formatted}\n" \
          "     got: #{@operator.to_s.gsub(/./, ' ')} #{actual_formatted}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          message = "`expect(#{actual_formatted}).not_to " \
                    "be #{@operator} #{expected_formatted}`"
          if [:<, :>, :<=, :>=].include?(@operator)
            message + " not only FAILED, it is a bit confusing."
          else
            message
          end
        end

        # @api private
        # @return [String]
        def description
          "be #{@operator} #{expected_to_sentence}#{args_to_sentence}"
        end
      end

      # @api private
      # Provides the implementation of `be_<predicate>`.
      # Not intended to be instantiated directly.
      class BePredicate < BaseMatcher
        include BeHelpers

        def initialize(*args, &block)
          @expected = parse_expected(args.shift)
          @args = args
          @block = block
        end

        def matches?(actual, &block)
          @actual  = actual
          @block ||= block
          predicate_accessible? && predicate_matches?
        end

        def does_not_match?(actual, &block)
          @actual  = actual
          @block ||= block
          predicate_accessible? && !predicate_matches?
        end

        # @api private
        # @return [String]
        def failure_message
          failure_message_expecting(true)
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          failure_message_expecting(false)
        end

        # @api private
        # @return [String]
        def description
          "#{prefix_to_sentence}#{expected_to_sentence}#{args_to_sentence}"
        end

      private

        def predicate_accessible?
          actual.respond_to?(predicate) || actual.respond_to?(present_tense_predicate)
        end

        # support 1.8.7, evaluate once at load time for performance
        if String === methods.first
          # :nocov:
          def private_predicate?
            @actual.private_methods.include? predicate.to_s
          end
          # :nocov:
        else
          def private_predicate?
            @actual.private_methods.include? predicate
          end
        end

        def predicate_matches?
          method_name = actual.respond_to?(predicate) ? predicate : present_tense_predicate
          @predicate_matches = actual.__send__(method_name, *@args, &@block)
        end

        def predicate
          :"#{@expected}?"
        end

        def present_tense_predicate
          :"#{@expected}s?"
        end

        def parse_expected(expected)
          @prefix, expected = prefix_and_expected(expected)
          expected
        end

        def prefix_and_expected(symbol)
          Matchers::BE_PREDICATE_REGEX.match(symbol.to_s).captures.compact
        end

        def prefix_to_sentence
          EnglishPhrasing.split_words(@prefix)
        end

        def failure_message_expecting(value)
          validity_message ||
            "expected `#{actual_formatted}.#{predicate}#{args_to_s}` to return #{value}, got #{description_of @predicate_matches}"
        end

        def validity_message
          return nil if predicate_accessible?

          msg = "expected #{actual_formatted} to respond to `#{predicate}`".dup

          if private_predicate?
            msg << " but `#{predicate}` is a private method"
          elsif predicate == :true?
            msg << " or perhaps you meant `be true` or `be_truthy`"
          elsif predicate == :false?
            msg << " or perhaps you meant `be false` or `be_falsey`"
          end

          msg
        end
      end
    end
  end
end
