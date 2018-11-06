RSpec::Support.require_rspec_core "bisect/shell_command"
RSpec::Support.require_rspec_core "bisect/example_minimizer"
RSpec::Support.require_rspec_core "bisect/utilities"
RSpec::Support.require_rspec_core "formatters/bisect_progress_formatter"

module RSpec
  module Core
    module Bisect
      # The main entry point into the bisect logic. Coordinates among:
      #   - Bisect::ShellCommand: Generates shell commands to run spec subsets
      #   - Bisect::ExampleMinimizer: Contains the core bisect logic.
      #   - A bisect runner: runs a set of examples and returns the results.
      #   - A bisect formatter: provides progress updates to the user.
      # @private
      class Coordinator
        def self.bisect_with(spec_runner, original_cli_args, formatter)
          new(spec_runner, original_cli_args, formatter).bisect
        end

        def initialize(spec_runner, original_cli_args, formatter)
          @spec_runner   = spec_runner
          @shell_command = ShellCommand.new(original_cli_args)
          @notifier      = Bisect::Notifier.new(formatter)
        end

        def bisect
          repro = start_bisect_runner do |runner|
            minimizer = ExampleMinimizer.new(@shell_command, runner, @notifier)

            gracefully_abort_on_sigint(minimizer)
            minimizer.find_minimal_repro
            minimizer.repro_command_for_currently_needed_ids
          end

          @notifier.publish(:bisect_repro_command, :repro => repro)

          true
        rescue BisectFailedError => e
          @notifier.publish(:bisect_failed, :failure_explanation => e.message)
          false
        ensure
          @notifier.publish(:close)
        end

      private

        def start_bisect_runner(&block)
          klass = @spec_runner.configuration.bisect_runner_class
          klass.start(@shell_command, @spec_runner, &block)
        end

        def gracefully_abort_on_sigint(minimizer)
          trap('INT') do
            repro = minimizer.repro_command_for_currently_needed_ids
            @notifier.publish(:bisect_aborted, :repro => repro)
            exit(1)
          end
        end
      end
    end
  end
end
