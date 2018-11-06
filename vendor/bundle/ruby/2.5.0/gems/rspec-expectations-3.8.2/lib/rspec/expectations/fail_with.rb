module RSpec
  module Expectations
    class << self
      # @private
      class Differ
        # @private
        OBJECT_PREPARER = lambda do |object|
          RSpec::Matchers::Composable.surface_descriptions_in(object)
        end
      end

      # @private
      def differ
        RSpec::Support::Differ.new(
          :object_preparer => Differ::OBJECT_PREPARER,
          :color => RSpec::Matchers.configuration.color?
        )
      end

      # Raises an RSpec::Expectations::ExpectationNotMetError with message.
      # @param [String] message
      # @param [Object] expected
      # @param [Object] actual
      #
      # Adds a diff to the failure message when `expected` and `actual` are
      # both present.
      def fail_with(message, expected=nil, actual=nil)
        unless message
          raise ArgumentError, "Failure message is nil. Does your matcher define the " \
                               "appropriate failure_message[_when_negated] method to return a string?"
        end

        message = ::RSpec::Matchers::ExpectedsForMultipleDiffs.from(expected).message_with_diff(message, differ, actual)

        RSpec::Support.notify_failure(RSpec::Expectations::ExpectationNotMetError.new message)
      end
    end
  end
end
