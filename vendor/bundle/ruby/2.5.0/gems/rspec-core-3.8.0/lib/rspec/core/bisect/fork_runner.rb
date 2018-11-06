require 'stringio'
RSpec::Support.require_rspec_core "formatters/base_bisect_formatter"
RSpec::Support.require_rspec_core "bisect/utilities"

module RSpec
  module Core
    module Bisect
      # A Bisect runner that runs requested subsets of the suite by forking
      # sub-processes. The master process bootstraps RSpec and the application
      # environment (including preloading files specified via `--require`) so
      # that the individual spec runs do not have to re-pay that cost.  Each
      # spec run happens in a forked process, ensuring that the spec files are
      # not loaded in the main process.
      #
      # For most projects, bisections that use `ForkRunner` instead of
      # `ShellRunner` will finish significantly faster, because the `ShellRunner`
      # pays the cost of booting RSpec and the app environment on _every_ run of
      # a subset. In contrast, `ForkRunner` pays that cost only once.
      #
      # However, not all projects can use `ForkRunner`. Obviously, on platforms
      # that do not support forking (e.g. Windows), it cannot be used. In addition,
      # it can cause problems for some projects that put side-effectful spec
      # bootstrapping logic that should run on every spec run directly at the top
      # level in a file loaded by `--require`, rather than in a `before(:suite)`
      # hook. For example, consider a project that relies on some top-level logic
      # in `spec_helper` to boot a Redis server for the test suite, intending the
      # Redis bootstrapping to happen on every spec run. With `ShellRunner`, the
      # bootstrapping logic will happen for each run of any subset of the suite,
      # but for `ForkRunner`, such logic will only get run once, when the
      # `RunDispatcher` boots the application environment. This might cause
      # problems. The solution is for users to move the bootstrapping logic into
      # a `before(:suite)` hook, or use the slower `ShellRunner`.
      #
      # @private
      class ForkRunner
        def self.start(shell_command, spec_runner)
          instance = new(shell_command, spec_runner)
          yield instance
        ensure
          instance.shutdown
        end

        def self.name
          :fork
        end

        def initialize(shell_command, spec_runner)
          @shell_command = shell_command
          @channel = Channel.new
          @run_dispatcher = RunDispatcher.new(spec_runner, @channel)
        end

        def run(locations)
          run_descriptor = ExampleSetDescriptor.new(locations, original_results.failed_example_ids)
          dispatch_run(run_descriptor)
        end

        def original_results
          @original_results ||= dispatch_run(ExampleSetDescriptor.new(
            @shell_command.original_locations, []))
        end

        def shutdown
          @channel.close
        end

      private

        def dispatch_run(run_descriptor)
          @run_dispatcher.dispatch_specs(run_descriptor)
          @channel.receive.tap do |result|
            if result.is_a?(String)
              raise BisectFailedError.for_failed_spec_run(result)
            end
          end
        end

        # @private
        class RunDispatcher
          def initialize(runner, channel)
            @runner = runner
            @channel = channel

            @spec_output = StringIO.new

            runner.configuration.tap do |c|
              c.reset_reporter
              c.output_stream = @spec_output
              c.error_stream = @spec_output
            end
          end

          def dispatch_specs(run_descriptor)
            pid = fork { run_specs(run_descriptor) }
            Process.waitpid(pid)
          end

        private

          def run_specs(run_descriptor)
            $stdout = $stderr = @spec_output
            formatter = CaptureFormatter.new(run_descriptor.failed_example_ids)

            @runner.configuration.tap do |c|
              c.files_or_directories_to_run = run_descriptor.all_example_ids
              c.formatter = formatter
              c.load_spec_files
            end

            # `announce_filters` has the side effect of implementing the logic
            # that honors `config.run_all_when_everything_filtered` so we need
            # to call it here. When we remove `run_all_when_everything_filtered`
            # (slated for RSpec 4), we can remove this call to `announce_filters`.
            @runner.world.announce_filters

            @runner.run_specs(@runner.world.ordered_example_groups)
            latest_run_results = formatter.results

            if latest_run_results.nil? || latest_run_results.all_example_ids.empty?
              @channel.send(@spec_output.string)
            else
              @channel.send(latest_run_results)
            end
          end
        end

        class CaptureFormatter < Formatters::BaseBisectFormatter
          attr_accessor :results
          alias_method :notify_results, :results=
        end
      end
    end
  end
end
