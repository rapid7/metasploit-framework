require 'drb/drb'
RSpec::Support.require_rspec_core "formatters/base_bisect_formatter"

module RSpec
  module Core
    module Formatters
      # Used by `--bisect`. When it shells out and runs a portion of the suite, it uses
      # this formatter as a means to have the status reported back to it, via DRb.
      #
      # Note that since DRb calls carry considerable overhead compared to normal
      # method calls, we try to minimize the number of DRb calls for perf reasons,
      # opting to communicate only at the start and the end of the run, rather than
      # after each example.
      # @private
      class BisectDRbFormatter < BaseBisectFormatter
        def initialize(_output)
          drb_uri = "druby://localhost:#{RSpec.configuration.drb_port}"
          @bisect_server = DRbObject.new_with_uri(drb_uri)
          RSpec.configuration.files_or_directories_to_run = @bisect_server.files_or_directories_to_run
          super(Set.new(@bisect_server.expected_failures))
        end

        def notify_results(results)
          @bisect_server.latest_run_results = results
        end
      end
    end
  end
end
