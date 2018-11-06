require 'rspec/support'

module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for operator matchers.
      # Not intended to be instantiated directly.
      # Only available for use with `should`.
      class OperatorMatcher
        class << self
          # @private
          def registry
            @registry ||= {}
          end

          # @private
          def register(klass, operator, matcher)
            registry[klass] ||= {}
            registry[klass][operator] = matcher
          end

          # @private
          def unregister(klass, operator)
            registry[klass] && registry[klass].delete(operator)
          end

          # @private
          def get(klass, operator)
            klass.ancestors.each do |ancestor|
              matcher = registry[ancestor] && registry[ancestor][operator]
              return matcher if matcher
            end

            nil
          end
        end

        register Enumerable, '=~', BuiltIn::ContainExactly

        def initialize(actual)
          @actual = actual
        end

        # @private
        def self.use_custom_matcher_or_delegate(operator)
          define_method(operator) do |expected|
            if !has_non_generic_implementation_of?(operator) && (matcher = OperatorMatcher.get(@actual.class, operator))
              @actual.__send__(::RSpec::Matchers.last_expectation_handler.should_method, matcher.new(expected))
            else
              eval_match(@actual, operator, expected)
            end
          end

          negative_operator = operator.sub(/^=/, '!')
          if negative_operator != operator && respond_to?(negative_operator)
            define_method(negative_operator) do |_expected|
              opposite_should = ::RSpec::Matchers.last_expectation_handler.opposite_should_method
              raise "RSpec does not support `#{::RSpec::Matchers.last_expectation_handler.should_method} #{negative_operator} expected`.  " \
                "Use `#{opposite_should} #{operator} expected` instead."
            end
          end
        end

        ['==', '===', '=~', '>', '>=', '<', '<='].each do |operator|
          use_custom_matcher_or_delegate operator
        end

        # @private
        def fail_with_message(message)
          RSpec::Expectations.fail_with(message, @expected, @actual)
        end

        # @api private
        # @return [String]
        def description
          "#{@operator} #{RSpec::Support::ObjectFormatter.format(@expected)}"
        end

      private

        def has_non_generic_implementation_of?(op)
          Support.method_handle_for(@actual, op).owner != ::Kernel
        rescue NameError
          false
        end

        def eval_match(actual, operator, expected)
          ::RSpec::Matchers.last_matcher = self
          @operator, @expected = operator, expected
          __delegate_operator(actual, operator, expected)
        end
      end

      # @private
      # Handles operator matcher for `should`.
      class PositiveOperatorMatcher < OperatorMatcher
        def __delegate_operator(actual, operator, expected)
          if actual.__send__(operator, expected)
            true
          else
            expected_formatted = RSpec::Support::ObjectFormatter.format(expected)
            actual_formatted   = RSpec::Support::ObjectFormatter.format(actual)

            if ['==', '===', '=~'].include?(operator)
              fail_with_message("expected: #{expected_formatted}\n     got: #{actual_formatted} (using #{operator})")
            else
              fail_with_message("expected: #{operator} #{expected_formatted}\n     got: #{operator.gsub(/./, ' ')} #{actual_formatted}")
            end
          end
        end
      end

      # @private
      # Handles operator matcher for `should_not`.
      class NegativeOperatorMatcher < OperatorMatcher
        def __delegate_operator(actual, operator, expected)
          return false unless actual.__send__(operator, expected)

          expected_formatted = RSpec::Support::ObjectFormatter.format(expected)
          actual_formatted   = RSpec::Support::ObjectFormatter.format(actual)

          fail_with_message("expected not: #{operator} #{expected_formatted}\n         got: #{operator.gsub(/./, ' ')} #{actual_formatted}")
        end
      end
    end
  end
end
