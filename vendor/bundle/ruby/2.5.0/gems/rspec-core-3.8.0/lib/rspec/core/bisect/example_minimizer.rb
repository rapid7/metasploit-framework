RSpec::Support.require_rspec_core "bisect/utilities"

module RSpec
  module Core
    module Bisect
      # @private
      # Contains the core bisect logic. Searches for examples we can ignore by
      # repeatedly running different subsets of the suite.
      class ExampleMinimizer
        attr_reader :shell_command, :runner, :all_example_ids, :failed_example_ids
        attr_accessor :remaining_ids

        def initialize(shell_command, runner, notifier)
          @shell_command = shell_command
          @runner        = runner
          @notifier      = notifier
        end

        def find_minimal_repro
          prep

          _, duration = track_duration do
            bisect(non_failing_example_ids)
          end

          notify(:bisect_complete, :duration => duration,
                                   :original_non_failing_count => non_failing_example_ids.size,
                                   :remaining_count => remaining_ids.size)

          remaining_ids + failed_example_ids
        end

        def bisect(candidate_ids)
          notify(:bisect_dependency_check_started)
          if get_expected_failures_for?([])
            notify(:bisect_dependency_check_failed)
            self.remaining_ids = []
            return
          end
          notify(:bisect_dependency_check_passed)

          bisect_over(candidate_ids)
        end

        def bisect_over(candidate_ids)
          return if candidate_ids.one?

          notify(
            :bisect_round_started,
            :candidate_range => example_range(candidate_ids),
            :candidates_count => candidate_ids.size
          )

          slice_size = (candidate_ids.length / 2.0).ceil
          lhs, rhs = candidate_ids.each_slice(slice_size).to_a

          ids_to_ignore, duration = track_duration do
            [lhs, rhs].find do |ids|
              get_expected_failures_for?(remaining_ids - ids)
            end
          end

          if ids_to_ignore
            self.remaining_ids -= ids_to_ignore
            notify(
              :bisect_round_ignoring_ids,
              :ids_to_ignore => ids_to_ignore,
              :ignore_range => example_range(ids_to_ignore),
              :remaining_ids => remaining_ids,
              :duration => duration
            )
            bisect_over(candidate_ids - ids_to_ignore)
          else
            notify(
              :bisect_round_detected_multiple_culprits,
              :duration => duration
            )
            bisect_over(lhs)
            bisect_over(rhs)
          end
        end

        def currently_needed_ids
          remaining_ids + failed_example_ids
        end

        def repro_command_for_currently_needed_ids
          return shell_command.repro_command_from(currently_needed_ids) if remaining_ids
          "(Not yet enough information to provide any repro command)"
        end

        # @private
        # Convenience class for describing a subset of the candidate examples
        ExampleRange = Struct.new(:start, :finish) do
          def description
            if start == finish
              "example #{start}"
            else
              "examples #{start}-#{finish}"
            end
          end
        end

      private

        def example_range(ids)
          ExampleRange.new(
            non_failing_example_ids.find_index(ids.first) + 1,
            non_failing_example_ids.find_index(ids.last) + 1
          )
        end

        def prep
          notify(:bisect_starting, :original_cli_args => shell_command.original_cli_args,
                                   :bisect_runner => runner.class.name)

          _, duration = track_duration do
            original_results    = runner.original_results
            @all_example_ids    = original_results.all_example_ids
            @failed_example_ids = original_results.failed_example_ids
            @remaining_ids      = non_failing_example_ids
          end

          if @failed_example_ids.empty?
            raise BisectFailedError, "\n\nNo failures found. Bisect only works " \
                  "in the presence of one or more failing examples."
          else
            notify(:bisect_original_run_complete, :failed_example_ids => failed_example_ids,
                                                  :non_failing_example_ids => non_failing_example_ids,
                                                  :duration => duration)
          end
        end

        def non_failing_example_ids
          @non_failing_example_ids ||= all_example_ids - failed_example_ids
        end

        def get_expected_failures_for?(ids)
          ids_to_run = ids + failed_example_ids
          notify(
            :bisect_individual_run_start,
            :command => shell_command.repro_command_from(ids_to_run),
            :ids_to_run => ids_to_run
          )

          results, duration = track_duration { runner.run(ids_to_run) }
          notify(:bisect_individual_run_complete, :duration => duration, :results => results)

          abort_if_ordering_inconsistent(results)
          (failed_example_ids & results.failed_example_ids) == failed_example_ids
        end

        def track_duration
          start = ::RSpec::Core::Time.now
          [yield, ::RSpec::Core::Time.now - start]
        end

        def abort_if_ordering_inconsistent(results)
          expected_order = all_example_ids & results.all_example_ids
          return if expected_order == results.all_example_ids

          raise BisectFailedError, "\n\nThe example ordering is inconsistent. " \
                "`--bisect` relies upon consistent ordering (e.g. by passing " \
                "`--seed` if you're using random ordering) to work properly."
        end

        def notify(*args)
          @notifier.publish(*args)
        end
      end
    end
  end
end
