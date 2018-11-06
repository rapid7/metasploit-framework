module RSpec
  module Rails
    module Matchers
      # @private
      class BeANewRecord < RSpec::Matchers::BuiltIn::BaseMatcher
        def matches?(actual)
          actual.new_record?
        end

        def failure_message
          "expected #{actual.inspect} to be a new record, but was persisted"
        end

        def failure_message_when_negated
          "expected #{actual.inspect} to be persisted, but was a new record"
        end
      end

      # @api public
      # Passes if actual returns `true` for `new_record?`.
      #
      # @example
      #     get :new
      #     expect(assigns(:thing)).to be_new_record
      def be_new_record
        BeANewRecord.new
      end
    end
  end
end
