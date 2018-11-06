module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `equal`.
      # Not intended to be instantiated directly.
      class Equal < BaseMatcher
        # @api private
        # @return [String]
        def failure_message
          if expected_is_a_literal_singleton?
            simple_failure_message
          else
            detailed_failure_message
          end
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          <<-MESSAGE

expected not #{inspect_object(actual)}
         got #{inspect_object(expected)}

Compared using equal?, which compares object identity.

MESSAGE
        end

        # @api private
        # @return [Boolean]
        def diffable?
          !expected_is_a_literal_singleton?
        end

      private

        def match(expected, actual)
          actual.equal? expected
        end

        LITERAL_SINGLETONS = [true, false, nil]

        def expected_is_a_literal_singleton?
          LITERAL_SINGLETONS.include?(expected)
        end

        def actual_inspected
          if LITERAL_SINGLETONS.include?(actual)
            actual_formatted
          else
            inspect_object(actual)
          end
        end

        def simple_failure_message
          "\nexpected #{expected_formatted}\n     got #{actual_inspected}\n"
        end

        def detailed_failure_message
          <<-MESSAGE

expected #{inspect_object(expected)}
     got #{inspect_object(actual)}

Compared using equal?, which compares object identity,
but expected and actual are not the same object. Use
`expect(actual).to eq(expected)` if you don't care about
object identity in this example.

MESSAGE
        end

        def inspect_object(o)
          "#<#{o.class}:#{o.object_id}> => #{RSpec::Support::ObjectFormatter.format(o)}"
        end
      end
    end
  end
end
