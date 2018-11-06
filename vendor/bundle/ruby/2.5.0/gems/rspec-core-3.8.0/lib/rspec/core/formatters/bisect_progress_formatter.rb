RSpec::Support.require_rspec_core "formatters/base_text_formatter"

module RSpec
  module Core
    module Formatters
      # @private
      # Produces progress output while bisecting.
      class BisectProgressFormatter < BaseTextFormatter
        def initialize(output, bisect_runner)
          super(output)
          @bisect_runner = bisect_runner
        end

        def bisect_starting(notification)
          @round_count = 0
          output.puts bisect_started_message(notification)
          output.print "Running suite to find failures..."
        end

        def bisect_original_run_complete(notification)
          failures     = Helpers.pluralize(notification.failed_example_ids.size, "failing example")
          non_failures = Helpers.pluralize(notification.non_failing_example_ids.size, "non-failing example")

          output.puts " (#{Helpers.format_duration(notification.duration)})"
          output.puts "Starting bisect with #{failures} and #{non_failures}."
        end

        def bisect_dependency_check_started(_notification)
          output.print "Checking that failure(s) are order-dependent.."
        end

        def bisect_dependency_check_passed(_notification)
          output.puts " failure appears to be order-dependent"
        end

        def bisect_dependency_check_failed(_notification)
          output.puts " failure(s) do not require any non-failures to run first"

          if @bisect_runner == :fork
            output.puts
            output.puts "=" * 80
            output.puts "NOTE: this bisect run used `config.bisect_runner = :fork`, which generally"
            output.puts "provides significantly faster bisection runs than the old shell-based runner,"
            output.puts "but may inaccurately report that no non-failures are required. If this result"
            output.puts "is unexpected, consider setting `config.bisect_runner = :shell` and trying again."
            output.puts "=" * 80
          end
        end

        def bisect_round_started(notification, include_trailing_space=true)
          @round_count += 1
          range_desc = notification.candidate_range.description

          output.print "\nRound #{@round_count}: bisecting over non-failing #{range_desc}"
          output.print " " if include_trailing_space
        end

        def bisect_round_ignoring_ids(notification)
          range_desc = notification.ignore_range.description

          output.print " ignoring #{range_desc}"
          output.print " (#{Helpers.format_duration(notification.duration)})"
        end

        def bisect_round_detected_multiple_culprits(notification)
          output.print " multiple culprits detected - splitting candidates"
          output.print " (#{Helpers.format_duration(notification.duration)})"
        end

        def bisect_individual_run_complete(_)
          output.print '.'
        end

        def bisect_complete(notification)
          output.puts "\nBisect complete! Reduced necessary non-failing examples " \
                      "from #{notification.original_non_failing_count} to " \
                      "#{notification.remaining_count} in " \
                      "#{Helpers.format_duration(notification.duration)}."
        end

        def bisect_repro_command(notification)
          output.puts "\nThe minimal reproduction command is:\n  #{notification.repro}"
        end

        def bisect_failed(notification)
          output.puts "\nBisect failed! #{notification.failure_explanation}"
        end

        def bisect_aborted(notification)
          output.puts "\n\nBisect aborted!"
          output.puts "\nThe most minimal reproduction command discovered so far is:\n  #{notification.repro}"
        end

      private

        def bisect_started_message(notification)
          options = notification.original_cli_args.join(' ')
          "Bisect started using options: #{options.inspect}"
        end
      end

      # @private
      # Produces detailed debug output while bisecting. Used when bisect is
      # performed with `--bisect=verbose`. Designed to provide details for
      # us when we need to troubleshoot bisect bugs.
      class BisectDebugFormatter < BisectProgressFormatter
        def bisect_original_run_complete(notification)
          output.puts " (#{Helpers.format_duration(notification.duration)})"

          output.puts " - #{describe_ids 'Failing examples', notification.failed_example_ids}"
          output.puts " - #{describe_ids 'Non-failing examples', notification.non_failing_example_ids}"
        end

        def bisect_individual_run_start(notification)
          output.print "\n - Running: #{notification.command}"
        end

        def bisect_individual_run_complete(notification)
          output.print " (#{Helpers.format_duration(notification.duration)})"
        end

        def bisect_dependency_check_passed(_notification)
          output.print "\n - Failure appears to be order-dependent"
        end

        def bisect_dependency_check_failed(_notification)
          output.print "\n - Failure is not order-dependent"
        end

        def bisect_round_started(notification)
          super(notification, false)
        end

        def bisect_round_ignoring_ids(notification)
          output.print "\n - #{describe_ids 'Examples we can safely ignore', notification.ids_to_ignore}"
          output.print "\n - #{describe_ids 'Remaining non-failing examples', notification.remaining_ids}"
        end

        def bisect_round_detected_multiple_culprits(_notification)
          output.print "\n - Multiple culprits detected - splitting candidates"
        end

      private

        def describe_ids(description, ids)
          organized_ids = Formatters::Helpers.organize_ids(ids)
          formatted_ids = organized_ids.map { |id| "    - #{id}" }.join("\n")
          "#{description} (#{ids.size}):\n#{formatted_ids}"
        end

        def bisect_started_message(notification)
          "#{super} and bisect runner: #{notification.bisect_runner.inspect}"
        end
      end
    end
  end
end
