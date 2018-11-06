module RSpec
  module Rails
    module Matchers
      # @private
      class BeValid < RSpec::Matchers::BuiltIn::Be
        def initialize(*args)
          @args = args
        end

        def matches?(actual)
          @actual = actual
          actual.valid?(*@args)
        end

        def failure_message
          message = "expected #{actual.inspect} to be valid"

          if actual.respond_to?(:errors)
            errors = if actual.errors.respond_to?(:full_messages)
                       actual.errors.full_messages
                     else
                       actual.errors
                     end

            message << ", but got errors: #{errors.map(&:to_s).join(', ')}"
          end

          message
        end

        def failure_message_when_negated
          "expected #{actual.inspect} not to be valid"
        end
      end

      # @api public
      # Passes if the given model instance's `valid?` method is true, meaning
      # all of the `ActiveModel::Validations` passed and no errors exist. If a
      # message is not given, a default message is shown listing each error.
      #
      # @example
      #     thing = Thing.new
      #     expect(thing).to be_valid
      def be_valid(*args)
        BeValid.new(*args)
      end
    end
  end
end
