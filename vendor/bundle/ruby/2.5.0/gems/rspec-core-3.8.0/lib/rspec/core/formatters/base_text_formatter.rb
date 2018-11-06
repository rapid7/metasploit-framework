RSpec::Support.require_rspec_core "formatters/base_formatter"

module RSpec
  module Core
    module Formatters
      # Base for all of RSpec's built-in formatters. See
      # RSpec::Core::Formatters::BaseFormatter to learn more about all of the
      # methods called by the reporter.
      #
      # @see RSpec::Core::Formatters::BaseFormatter
      # @see RSpec::Core::Reporter
      class BaseTextFormatter < BaseFormatter
        Formatters.register self,
                            :message, :dump_summary, :dump_failures, :dump_pending, :seed

        # @api public
        #
        # Used by the reporter to send messages to the output stream.
        #
        # @param notification [MessageNotification] containing message
        def message(notification)
          output.puts notification.message
        end

        # @api public
        #
        # Dumps detailed information about each example failure.
        #
        # @param notification [NullNotification]
        def dump_failures(notification)
          return if notification.failure_notifications.empty?
          output.puts notification.fully_formatted_failed_examples
        end

        # @api public
        #
        # This method is invoked after the dumping of examples and failures.
        # Each parameter is assigned to a corresponding attribute.
        #
        # @param summary [SummaryNotification] containing duration,
        #   example_count, failure_count and pending_count
        def dump_summary(summary)
          output.puts summary.fully_formatted
        end

        # @private
        def dump_pending(notification)
          return if notification.pending_examples.empty?
          output.puts notification.fully_formatted_pending_examples
        end

        # @private
        def seed(notification)
          return unless notification.seed_used?
          output.puts notification.fully_formatted
        end

        # @api public
        #
        # Invoked at the end of a suite run. Allows the formatter to do any
        # tidying up, but be aware that formatter output streams may be used
        # elsewhere so don't actually close them.
        #
        # @param _notification [NullNotification] (Ignored)
        def close(_notification)
          return if output.closed?

          output.puts

          output.flush
        end
      end
    end
  end
end
