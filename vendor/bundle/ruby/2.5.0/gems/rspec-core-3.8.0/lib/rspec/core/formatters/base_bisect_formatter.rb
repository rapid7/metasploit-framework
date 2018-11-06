RSpec::Support.require_rspec_core "bisect/utilities"

module RSpec
  module Core
    module Formatters
      # Contains common logic for formatters used by `--bisect` to communicate results
      # back to the bisect runner.
      #
      # Subclasses must define a `notify_results(all_example_ids, failed_example_ids)`
      # method.
      # @private
      class BaseBisectFormatter
        def self.inherited(formatter)
          Formatters.register formatter, :start_dump, :example_failed, :example_finished
        end

        def initialize(expected_failures)
          @all_example_ids = []
          @failed_example_ids = []
          @remaining_failures = expected_failures
        end

        def example_failed(notification)
          @failed_example_ids << notification.example.id
        end

        def example_finished(notification)
          @all_example_ids << notification.example.id
          return unless @remaining_failures.include?(notification.example.id)
          @remaining_failures.delete(notification.example.id)

          status = notification.example.execution_result.status
          return if status == :failed && !@remaining_failures.empty?
          RSpec.world.wants_to_quit = true
        end

        def start_dump(_notification)
          # `notify_results` is defined in the subclass
          notify_results(Bisect::ExampleSetDescriptor.new(
            @all_example_ids, @failed_example_ids))
        end
      end
    end
  end
end
