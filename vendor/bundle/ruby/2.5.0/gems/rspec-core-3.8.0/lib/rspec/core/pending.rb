module RSpec
  module Core
    # Provides methods to mark examples as pending. These methods are available
    # to be called from within any example or hook.
    module Pending
      # Raised in the middle of an example to indicate that it should be marked
      # as skipped.
      class SkipDeclaredInExample < StandardError
        attr_reader :argument

        def initialize(argument)
          @argument = argument
        end
      end

      # If Test::Unit is loaded, we'll use its error as baseclass, so that
      # Test::Unit will report unmet RSpec expectations as failures rather than
      # errors.
      begin
        class PendingExampleFixedError < Test::Unit::AssertionFailedError; end
      rescue
        class PendingExampleFixedError < StandardError; end
      end

      # @private
      NO_REASON_GIVEN = 'No reason given'

      # @private
      NOT_YET_IMPLEMENTED = 'Not yet implemented'

      # @overload pending()
      # @overload pending(message)
      #
      # Marks an example as pending. The rest of the example will still be
      # executed, and if it passes the example will fail to indicate that the
      # pending can be removed.
      #
      # @param message [String] optional message to add to the summary report.
      #
      # @example
      #     describe "an example" do
      #       # reported as "Pending: no reason given"
      #       it "is pending with no message" do
      #         pending
      #         raise "broken"
      #       end
      #
      #       # reported as "Pending: something else getting finished"
      #       it "is pending with a custom message" do
      #         pending("something else getting finished")
      #         raise "broken"
      #       end
      #     end
      #
      # @note `before(:example)` hooks are eval'd when you use the `pending`
      #   method within an example. If you want to declare an example `pending`
      #   and bypass the `before` hooks as well, you can pass `:pending => true`
      #   to the `it` method:
      #
      #       it "does something", :pending => true do
      #         # ...
      #       end
      #
      #   or pass `:pending => "something else getting finished"` to add a
      #   message to the summary report:
      #
      #       it "does something", :pending => "something else getting finished" do
      #         # ...
      #       end
      def pending(message=nil)
        current_example = RSpec.current_example

        if block_given?
          raise ArgumentError, <<-EOS.gsub(/^\s+\|/, '')
            |The semantics of `RSpec::Core::Pending#pending` have changed in
            |RSpec 3. In RSpec 2.x, it caused the example to be skipped. In
            |RSpec 3, the rest of the example is still run but is expected to
            |fail, and will be marked as a failure (rather than as pending) if
            |the example passes.
            |
            |Passing a block within an example is now deprecated. Marking the
            |example as pending provides the same behavior in RSpec 3 which was
            |provided only by the block in RSpec 2.x.
            |
            |Move the code in the block provided to `pending` into the rest of
            |the example body.
            |
            |Called from #{CallerFilter.first_non_rspec_line}.
            |
          EOS
        elsif current_example
          Pending.mark_pending! current_example, message
        else
          raise "`pending` may not be used outside of examples, such as in " \
                "before(:context). Maybe you want `skip`?"
        end
      end

      # @overload skip()
      # @overload skip(message)
      #
      # Marks an example as pending and skips execution.
      #
      # @param message [String] optional message to add to the summary report.
      #
      # @example
      #     describe "an example" do
      #       # reported as "Pending: no reason given"
      #       it "is skipped with no message" do
      #         skip
      #       end
      #
      #       # reported as "Pending: something else getting finished"
      #       it "is skipped with a custom message" do
      #         skip "something else getting finished"
      #       end
      #     end
      def skip(message=nil)
        current_example = RSpec.current_example

        Pending.mark_skipped!(current_example, message) if current_example

        raise SkipDeclaredInExample.new(message)
      end

      # @private
      #
      # Mark example as skipped.
      #
      # @param example [RSpec::Core::Example] the example to mark as skipped
      # @param message_or_bool [Boolean, String] the message to use, or true
      def self.mark_skipped!(example, message_or_bool)
        Pending.mark_pending! example, message_or_bool
        example.metadata[:skip] = true
      end

      # @private
      #
      # Mark example as pending.
      #
      # @param example [RSpec::Core::Example] the example to mark as pending
      # @param message_or_bool [Boolean, String] the message to use, or true
      def self.mark_pending!(example, message_or_bool)
        message = if !message_or_bool || !(String === message_or_bool)
                    NO_REASON_GIVEN
                  else
                    message_or_bool
                  end

        example.metadata[:pending] = true
        example.execution_result.pending_message = message
        example.execution_result.pending_fixed = false
      end

      # @private
      #
      # Mark example as fixed.
      #
      # @param example [RSpec::Core::Example] the example to mark as fixed
      def self.mark_fixed!(example)
        example.execution_result.pending_fixed = true
      end
    end
  end
end
