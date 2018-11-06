require 'drb/drb'
require 'drb/acl'
RSpec::Support.require_rspec_core "bisect/utilities"

module RSpec
  module Core
    # @private
    module Bisect
      # @private
      # A DRb server that receives run results from a separate RSpec process
      # started by the bisect process.
      class Server
        def self.run
          server = new
          server.start
          yield server
        ensure
          server.stop
        end

        def capture_run_results(files_or_directories_to_run=[], expected_failures=[])
          self.expected_failures  = expected_failures
          self.files_or_directories_to_run = files_or_directories_to_run
          self.latest_run_results = nil
          run_output = yield

          if latest_run_results.nil? || latest_run_results.all_example_ids.empty?
            raise BisectFailedError.for_failed_spec_run(run_output)
          end

          latest_run_results
        end

        def start
          # Only allow remote DRb requests from this machine.
          DRb.install_acl ACL.new(%w[ deny all allow localhost allow 127.0.0.1 ])

          # We pass `nil` as the first arg to allow it to pick a DRb port.
          @drb = DRb.start_service(nil, self)
        end

        def stop
          @drb.stop_service
        end

        def drb_port
          @drb_port ||= Integer(@drb.uri[/\d+$/])
        end

        # Fetched via DRb by the BisectDRbFormatter to determine when to abort.
        attr_accessor :expected_failures

        # Set via DRb by the BisectDRbFormatter with the results of the run.
        attr_accessor :latest_run_results

        # Fetched via DRb to tell clients which files to run
        attr_accessor :files_or_directories_to_run
      end
    end
  end
end
