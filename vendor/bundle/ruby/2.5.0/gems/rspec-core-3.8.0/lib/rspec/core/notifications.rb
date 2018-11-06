RSpec::Support.require_rspec_core "formatters/console_codes"
RSpec::Support.require_rspec_core "formatters/exception_presenter"
RSpec::Support.require_rspec_core "formatters/helpers"
RSpec::Support.require_rspec_core "shell_escape"

module RSpec::Core
  # Notifications are value objects passed to formatters to provide them
  # with information about a particular event of interest.
  module Notifications
    # @private
    module NullColorizer
      module_function

      def wrap(line, _code_or_symbol)
        line
      end
    end

    # The `StartNotification` represents a notification sent by the reporter
    # when the suite is started. It contains the expected amount of examples
    # to be executed, and the load time of RSpec.
    #
    # @attr count [Fixnum] the number counted
    # @attr load_time [Float] the number of seconds taken to boot RSpec
    #                         and load the spec files
    StartNotification = Struct.new(:count, :load_time)

    # The `ExampleNotification` represents notifications sent by the reporter
    # which contain information about the current (or soon to be) example.
    # It is used by formatters to access information about that example.
    #
    # @example
    #   def example_started(notification)
    #     puts "Hey I started #{notification.example.description}"
    #   end
    #
    # @attr example [RSpec::Core::Example] the current example
    ExampleNotification = Struct.new(:example)
    class ExampleNotification
      # @private
      def self.for(example)
        execution_result = example.execution_result

        return SkippedExampleNotification.new(example) if execution_result.example_skipped?
        return new(example) unless execution_result.status == :pending || execution_result.status == :failed

        klass = if execution_result.pending_fixed?
                  PendingExampleFixedNotification
                elsif execution_result.status == :pending
                  PendingExampleFailedAsExpectedNotification
                else
                  FailedExampleNotification
                end

        klass.new(example)
      end

      private_class_method :new
    end

    # The `ExamplesNotification` represents notifications sent by the reporter
    # which contain information about the suites examples.
    #
    # @example
    #   def stop(notification)
    #     puts "Hey I ran #{notification.examples.size}"
    #   end
    #
    class ExamplesNotification
      def initialize(reporter)
        @reporter = reporter
      end

      # @return [Array<RSpec::Core::Example>] list of examples
      def examples
        @reporter.examples
      end

      # @return [Array<RSpec::Core::Example>] list of failed examples
      def failed_examples
        @reporter.failed_examples
      end

      # @return [Array<RSpec::Core::Example>] list of pending examples
      def pending_examples
        @reporter.pending_examples
      end

      # @return [Array<RSpec::Core::Notifications::ExampleNotification>]
      #         returns examples as notifications
      def notifications
        @notifications ||= format_examples(examples)
      end

      # @return [Array<RSpec::Core::Notifications::FailedExampleNotification>]
      #         returns failed examples as notifications
      def failure_notifications
        @failed_notifications ||= format_examples(failed_examples)
      end

      # @return [Array<RSpec::Core::Notifications::SkippedExampleNotification,
      #                 RSpec::Core::Notifications::PendingExampleFailedAsExpectedNotification>]
      #         returns pending examples as notifications
      def pending_notifications
        @pending_notifications ||= format_examples(pending_examples)
      end

      # @return [String] The list of failed examples, fully formatted in the way
      #   that RSpec's built-in formatters emit.
      def fully_formatted_failed_examples(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        formatted = "\nFailures:\n"

        failure_notifications.each_with_index do |failure, index|
          formatted += failure.fully_formatted(index.next, colorizer)
        end

        formatted
      end

      # @return [String] The list of pending examples, fully formatted in the
      #   way that RSpec's built-in formatters emit.
      def fully_formatted_pending_examples(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        formatted = "\nPending: (Failures listed here are expected and do not affect your suite's status)\n".dup

        pending_notifications.each_with_index do |notification, index|
          formatted << notification.fully_formatted(index.next, colorizer)
        end

        formatted
      end

    private

      def format_examples(examples)
        examples.map do |example|
          ExampleNotification.for(example)
        end
      end
    end

    # The `FailedExampleNotification` extends `ExampleNotification` with
    # things useful for examples that have failure info -- typically a
    # failed or pending spec.
    #
    # @example
    #   def example_failed(notification)
    #     puts "Hey I failed :("
    #     puts "Here's my stack trace"
    #     puts notification.exception.backtrace.join("\n")
    #   end
    #
    # @attr [RSpec::Core::Example] example the current example
    # @see ExampleNotification
    class FailedExampleNotification < ExampleNotification
      public_class_method :new

      # @return [Exception] The example failure
      def exception
        @exception_presenter.exception
      end

      # @return [String] The example description
      def description
        @exception_presenter.description
      end

      # Returns the message generated for this failure line by line.
      #
      # @return [Array<String>] The example failure message
      def message_lines
        @exception_presenter.message_lines
      end

      # Returns the message generated for this failure colorized line by line.
      #
      # @param colorizer [#wrap] An object to colorize the message_lines by
      # @return [Array<String>] The example failure message colorized
      def colorized_message_lines(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        @exception_presenter.colorized_message_lines(colorizer)
      end

      # Returns the failures formatted backtrace.
      #
      # @return [Array<String>] the examples backtrace lines
      def formatted_backtrace
        @exception_presenter.formatted_backtrace
      end

      # Returns the failures colorized formatted backtrace.
      #
      # @param colorizer [#wrap] An object to colorize the message_lines by
      # @return [Array<String>] the examples colorized backtrace lines
      def colorized_formatted_backtrace(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        @exception_presenter.colorized_formatted_backtrace(colorizer)
      end

      # @return [String] The failure information fully formatted in the way that
      #   RSpec's built-in formatters emit.
      def fully_formatted(failure_number, colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        @exception_presenter.fully_formatted(failure_number, colorizer)
      end

      # @return [Array<string>] The failure information fully formatted in the way that
      #   RSpec's built-in formatters emit, split by line.
      def fully_formatted_lines(failure_number, colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        @exception_presenter.fully_formatted_lines(failure_number, colorizer)
      end

    private

      def initialize(example, exception_presenter=Formatters::ExceptionPresenter::Factory.new(example).build)
        @exception_presenter = exception_presenter
        super(example)
      end
    end

    # @deprecated Use {FailedExampleNotification} instead.
    class PendingExampleFixedNotification < FailedExampleNotification; end

    # @deprecated Use {FailedExampleNotification} instead.
    class PendingExampleFailedAsExpectedNotification < FailedExampleNotification; end

    # The `SkippedExampleNotification` extends `ExampleNotification` with
    # things useful for specs that are skipped.
    #
    # @attr [RSpec::Core::Example] example the current example
    # @see ExampleNotification
    class SkippedExampleNotification < ExampleNotification
      public_class_method :new

      # @return [String] The pending detail fully formatted in the way that
      #   RSpec's built-in formatters emit.
      def fully_formatted(pending_number, colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        formatted_caller = RSpec.configuration.backtrace_formatter.backtrace_line(example.location)

        [
          colorizer.wrap("\n  #{pending_number}) #{example.full_description}", :pending),
          "\n     ",
          Formatters::ExceptionPresenter::PENDING_DETAIL_FORMATTER.call(example, colorizer),
          "\n",
          colorizer.wrap("     # #{formatted_caller}\n", :detail)
        ].join("")
      end
    end

    # The `GroupNotification` represents notifications sent by the reporter
    # which contain information about the currently running (or soon to be)
    # example group. It is used by formatters to access information about that
    # group.
    #
    # @example
    #   def example_group_started(notification)
    #     puts "Hey I started #{notification.group.description}"
    #   end
    # @attr group [RSpec::Core::ExampleGroup] the current group
    GroupNotification = Struct.new(:group)

    # The `MessageNotification` encapsulates generic messages that the reporter
    # sends to formatters.
    #
    # @attr message [String] the message
    MessageNotification = Struct.new(:message)

    # The `SeedNotification` holds the seed used to randomize examples and
    # whether that seed has been used or not.
    #
    # @attr seed [Fixnum] the seed used to randomize ordering
    # @attr used [Boolean] whether the seed has been used or not
    SeedNotification = Struct.new(:seed, :used)
    class SeedNotification
      # @api
      # @return [Boolean] has the seed been used?
      def seed_used?
        !!used
      end
      private :used

      # @return [String] The seed information fully formatted in the way that
      #   RSpec's built-in formatters emit.
      def fully_formatted
        "\nRandomized with seed #{seed}\n"
      end
    end

    # The `SummaryNotification` holds information about the results of running
    # a test suite. It is used by formatters to provide information at the end
    # of the test run.
    #
    # @attr duration [Float] the time taken (in seconds) to run the suite
    # @attr examples [Array<RSpec::Core::Example>] the examples run
    # @attr failed_examples [Array<RSpec::Core::Example>] the failed examples
    # @attr pending_examples [Array<RSpec::Core::Example>] the pending examples
    # @attr load_time [Float] the number of seconds taken to boot RSpec
    #                         and load the spec files
    # @attr errors_outside_of_examples_count [Integer] the number of errors that
    #                                                  have occurred processing
    #                                                  the spec suite
    SummaryNotification = Struct.new(:duration, :examples, :failed_examples,
                                     :pending_examples, :load_time,
                                     :errors_outside_of_examples_count)
    class SummaryNotification
      # @api
      # @return [Fixnum] the number of examples run
      def example_count
        @example_count ||= examples.size
      end

      # @api
      # @return [Fixnum] the number of failed examples
      def failure_count
        @failure_count ||= failed_examples.size
      end

      # @api
      # @return [Fixnum] the number of pending examples
      def pending_count
        @pending_count ||= pending_examples.size
      end

      # @api
      # @return [String] A line summarising the result totals of the spec run.
      def totals_line
        summary = Formatters::Helpers.pluralize(example_count, "example") +
          ", " + Formatters::Helpers.pluralize(failure_count, "failure")
        summary += ", #{pending_count} pending" if pending_count > 0
        if errors_outside_of_examples_count > 0
          summary += (
            ", " +
            Formatters::Helpers.pluralize(errors_outside_of_examples_count, "error") +
            " occurred outside of examples"
          )
        end
        summary
      end

      # @api public
      #
      # Wraps the results line with colors based on the configured
      # colors for failure, pending, and success. Defaults to red,
      # yellow, green accordingly.
      #
      # @param colorizer [#wrap] An object which supports wrapping text with
      #                          specific colors.
      # @return [String] A colorized results line.
      def colorized_totals_line(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        if failure_count > 0 || errors_outside_of_examples_count > 0
          colorizer.wrap(totals_line, RSpec.configuration.failure_color)
        elsif pending_count > 0
          colorizer.wrap(totals_line, RSpec.configuration.pending_color)
        else
          colorizer.wrap(totals_line, RSpec.configuration.success_color)
        end
      end

      # @api public
      #
      # Formats failures into a rerunable command format.
      #
      # @param colorizer [#wrap] An object which supports wrapping text with
      #                          specific colors.
      # @return [String] A colorized summary line.
      def colorized_rerun_commands(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        "\nFailed examples:\n\n" +
        failed_examples.map do |example|
          colorizer.wrap("rspec #{rerun_argument_for(example)}", RSpec.configuration.failure_color) + " " +
          colorizer.wrap("# #{example.full_description}",   RSpec.configuration.detail_color)
        end.join("\n")
      end

      # @return [String] a formatted version of the time it took to run the
      #   suite
      def formatted_duration
        Formatters::Helpers.format_duration(duration)
      end

      # @return [String] a formatted version of the time it took to boot RSpec
      #   and load the spec files
      def formatted_load_time
        Formatters::Helpers.format_duration(load_time)
      end

      # @return [String] The summary information fully formatted in the way that
      #   RSpec's built-in formatters emit.
      def fully_formatted(colorizer=::RSpec::Core::Formatters::ConsoleCodes)
        formatted = "\nFinished in #{formatted_duration} " \
                    "(files took #{formatted_load_time} to load)\n" \
                    "#{colorized_totals_line(colorizer)}\n"

        unless failed_examples.empty?
          formatted += (colorized_rerun_commands(colorizer) + "\n")
        end

        formatted
      end

    private

      include RSpec::Core::ShellEscape

      def rerun_argument_for(example)
        location = example.location_rerun_argument
        return location unless duplicate_rerun_locations.include?(location)
        conditionally_quote(example.id)
      end

      def duplicate_rerun_locations
        @duplicate_rerun_locations ||= begin
          locations = RSpec.world.all_examples.map(&:location_rerun_argument)

          Set.new.tap do |s|
            locations.group_by { |l| l }.each do |l, ls|
              s << l if ls.count > 1
            end
          end
        end
      end
    end

    # The `ProfileNotification` holds information about the results of running a
    # test suite when profiling is enabled. It is used by formatters to provide
    # information at the end of the test run for profiling information.
    #
    # @attr duration [Float] the time taken (in seconds) to run the suite
    # @attr examples [Array<RSpec::Core::Example>] the examples run
    # @attr number_of_examples [Fixnum] the number of examples to profile
    # @attr example_groups [Array<RSpec::Core::Profiler>] example groups run
    class ProfileNotification
      def initialize(duration, examples, number_of_examples, example_groups)
        @duration = duration
        @examples = examples
        @number_of_examples = number_of_examples
        @example_groups = example_groups
      end
      attr_reader :duration, :examples, :number_of_examples

      # @return [Array<RSpec::Core::Example>] the slowest examples
      def slowest_examples
        @slowest_examples ||=
          examples.sort_by do |example|
            -example.execution_result.run_time
          end.first(number_of_examples)
      end

      # @return [Float] the time taken (in seconds) to run the slowest examples
      def slow_duration
        @slow_duration ||=
          slowest_examples.inject(0.0) do |i, e|
            i + e.execution_result.run_time
          end
      end

      # @return [String] the percentage of total time taken
      def percentage
        @percentage ||=
          begin
            time_taken = slow_duration / duration
            '%.1f' % ((time_taken.nan? ? 0.0 : time_taken) * 100)
          end
      end

      # @return [Array<RSpec::Core::Example>] the slowest example groups
      def slowest_groups
        @slowest_groups ||= calculate_slowest_groups
      end

    private

      def calculate_slowest_groups
        # stop if we've only one example group
        return {} if @example_groups.keys.length <= 1

        @example_groups.each_value do |hash|
          hash[:average] = hash[:total_time].to_f / hash[:count]
        end

        groups = @example_groups.sort_by { |_, hash| -hash[:average] }.first(number_of_examples)
        groups.map { |group, data| [group.location, data] }
      end
    end

    # The `DeprecationNotification` is issued by the reporter when a deprecated
    # part of RSpec is encountered. It represents information about the
    # deprecated call site.
    #
    # @attr message [String] A custom message about the deprecation
    # @attr deprecated [String] A custom message about the deprecation (alias of
    #   message)
    # @attr replacement [String] An optional replacement for the deprecation
    # @attr call_site [String] An optional call site from which the deprecation
    #   was issued
    DeprecationNotification = Struct.new(:deprecated, :message, :replacement, :call_site)
    class DeprecationNotification
      private_class_method :new

      # @api
      # Convenience way to initialize the notification
      def self.from_hash(data)
        new data[:deprecated], data[:message], data[:replacement], data[:call_site]
      end
    end

    # `NullNotification` represents a placeholder value for notifications that
    # currently require no information, but we may wish to extend in future.
    class NullNotification
    end

    # `CustomNotification` is used when sending custom events to formatters /
    # other registered listeners, it creates attributes based on supplied hash
    # of options.
    class CustomNotification < Struct
      # @param options [Hash] A hash of method / value pairs to create on this notification
      # @return [CustomNotification]
      #
      # Build a custom notification based on the supplied option key / values.
      def self.for(options={})
        return NullNotification if options.keys.empty?
        new(*options.keys).new(*options.values)
      end
    end
  end
end
