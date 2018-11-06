require 'open3'
RSpec::Support.require_rspec_core "bisect/server"

module RSpec
  module Core
    module Bisect
      # Provides an API to run the suite for a set of locations, using
      # the given bisect server to capture the results.
      #
      # Sets of specs are run by shelling out.
      # @private
      class ShellRunner
        def self.start(shell_command, _spec_runner)
          Server.run do |server|
            yield new(server, shell_command)
          end
        end

        def self.name
          :shell
        end

        def initialize(server, shell_command)
          @server        = server
          @shell_command = shell_command
        end

        def run(locations)
          run_locations(locations, original_results.failed_example_ids)
        end

        def original_results
          @original_results ||= run_locations(@shell_command.original_locations)
        end

      private

        def run_locations(*capture_args)
          @server.capture_run_results(*capture_args) do
            run_command @shell_command.command_for([], @server)
          end
        end

        # `Open3.capture2e` does not work on JRuby:
        # https://github.com/jruby/jruby/issues/2766
        if Open3.respond_to?(:capture2e) && !RSpec::Support::Ruby.jruby?
          def run_command(cmd)
            Open3.capture2e(@shell_command.bisect_environment_hash, cmd).first
          end
        else # for 1.8.7
          # :nocov:
          def run_command(cmd)
            out = err = nil

            original_spec_opts = ENV['SPEC_OPTS']
            ENV['SPEC_OPTS'] = @shell_command.spec_opts_without_bisect

            Open3.popen3(cmd) do |_, stdout, stderr|
              # Reading the streams blocks until the process is complete
              out = stdout.read
              err = stderr.read
            end

            "Stdout:\n#{out}\n\nStderr:\n#{err}"
          ensure
            ENV['SPEC_OPTS'] = original_spec_opts
          end
          # :nocov:
        end
      end
    end
  end
end
