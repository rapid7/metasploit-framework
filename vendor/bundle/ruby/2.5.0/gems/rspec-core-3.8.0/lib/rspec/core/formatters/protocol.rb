module RSpec
  module Core
    module Formatters
      # This class isn't loaded at runtime but serves to document all of the
      # notifications implemented as part of the standard interface. The
      # reporter will issue these during a normal test suite run, but a
      # formatter will only receive those notifications it has registered
      # itself to receive. To register a formatter call:
      #
      # `::RSpec::Core::Formatters.register class, :list, :of, :notifications`
      #
      # e.g.
      #
      # `::RSpec::Core::Formatters.register self, :start, :example_started`
      #
      # @see RSpec::Core::Formatters::BaseFormatter
      # @see RSpec::Core::Formatters::BaseTextFormatter
      # @see RSpec::Core::Reporter
      class Protocol
        # @method initialize(output)
        # @api public
        #
        # @param output [IO] the formatter output

        # @method start(notification)
        # @api public
        # @group Suite Notifications
        #
        # This method is invoked before any examples are run, right after
        # they have all been collected. This can be useful for special
        # formatters that need to provide progress on feedback (graphical ones).
        #
        # This will only be invoked once, and the next one to be invoked
        # is {#example_group_started}.
        #
        # @param notification [Notifications::StartNotification]

        # @method example_group_started(notification)
        # @api public
        # @group Group Notifications
        #
        # This method is invoked at the beginning of the execution of each
        # example group.
        #
        # The next method to be invoked after this is {#example_passed},
        # {#example_pending}, or {#example_group_finished}.
        #
        # @param notification [Notifications::GroupNotification] containing example_group
        #   subclass of {ExampleGroup}

        # @method example_group_finished(notification)
        # @api public
        # @group Group Notifications
        #
        # Invoked at the end of the execution of each example group.
        #
        # @param notification [Notifications::GroupNotification] containing example_group
        #   subclass of {ExampleGroup}

        # @method example_started(notification)
        # @api public
        # @group Example Notifications
        #
        # Invoked at the beginning of the execution of each example.
        #
        # @param notification [Notifications::ExampleNotification] containing example subclass
        #   of {Example}

        # @method example_finished(notification)
        # @api public
        # @group Example Notifications
        #
        # Invoked at the end of the execution of each example.
        #
        # @param notification [Notifications::ExampleNotification] containing example subclass
        #   of {Example}

        # @method example_passed(notification)
        # @api public
        # @group Example Notifications
        #
        # Invoked when an example passes.
        #
        # @param notification [Notifications::ExampleNotification] containing example subclass
        #   of {Example}

        # @method example_pending(notification)
        # @api public
        # @group Example Notifications
        #
        # Invoked when an example is pending.
        #
        # @param notification [Notifications::ExampleNotification] containing example subclass
        #   of {Example}

        # @method example_failed(notification)
        # @api public
        # @group Example Notifications
        #
        # Invoked when an example fails.
        #
        # @param notification [Notifications::ExampleNotification] containing example subclass
        #   of {Example}

        # @method message(notification)
        # @api public
        # @group Suite Notifications
        #
        # Used by the reporter to send messages to the output stream.
        #
        # @param notification [Notifications::MessageNotification] containing message

        # @method stop(notification)
        # @api public
        # @group Suite Notifications
        #
        # Invoked after all examples have executed, before dumping post-run
        # reports.
        #
        # @param notification [Notifications::NullNotification]

        # @method start_dump(notification)
        # @api public
        # @group Suite Notifications
        #
        # This method is invoked after all of the examples have executed. The
        # next method to be invoked after this one is {#dump_failures}
        # (BaseTextFormatter then calls {#dump_failures} once for each failed
        # example).
        #
        # @param notification [Notifications::NullNotification]

        # @method dump_failures(notification)
        # @api public
        # @group Suite Notifications
        #
        # Dumps detailed information about each example failure.
        #
        # @param notification [Notifications::NullNotification]

        # @method dump_summary(summary)
        # @api public
        # @group Suite Notifications
        #
        # This method is invoked after the dumping of examples and failures.
        # Each parameter is assigned to a corresponding attribute.
        #
        # @param summary [Notifications::SummaryNotification] containing duration,
        #   example_count, failure_count and pending_count

        # @method dump_profile(profile)
        # @api public
        # @group Suite Notifications
        #
        # This method is invoked after the dumping the summary if profiling is
        # enabled.
        #
        # @param profile [Notifications::ProfileNotification] containing duration,
        #   slowest_examples and slowest_example_groups

        # @method dump_pending(notification)
        # @api public
        # @group Suite Notifications
        #
        # Outputs a report of pending examples. This gets invoked
        # after the summary if option is set to do so.
        #
        # @param notification [Notifications::NullNotification]

        # @method close(notification)
        # @api public
        # @group Suite Notifications
        #
        # Invoked at the end of a suite run. Allows the formatter to do any
        # tidying up, but be aware that formatter output streams may be used
        # elsewhere so don't actually close them.
        #
        # @param notification [Notifications::NullNotification]
      end
    end
  end
end
