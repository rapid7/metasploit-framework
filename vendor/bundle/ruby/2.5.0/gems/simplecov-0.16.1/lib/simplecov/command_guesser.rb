# frozen_string_literal: true

#
# Helper that tries to find out what test suite is running (for SimpleCov.command_name)
#
module SimpleCov
  module CommandGuesser
    class << self
      # Storage for the original command line call that invoked the test suite.
      # This has got to be stored as early as possible because i.e. rake and test/unit 2
      # have a habit of tampering with ARGV, which makes i.e. the automatic distinction
      # between rails unit/functional/integration tests impossible without this cached
      # item.
      attr_accessor :original_run_command

      def guess
        from_env || from_command_line_options || from_defined_constants
      end

    private

      def from_env
        # If being run from inside parallel_tests set the command name according to the process number
        return unless ENV["PARALLEL_TEST_GROUPS"] && ENV["TEST_ENV_NUMBER"]
        number = ENV["TEST_ENV_NUMBER"]
        number = "1" if number.empty?
        "(#{number}/#{ENV['PARALLEL_TEST_GROUPS']})"
      end

      def from_command_line_options
        case original_run_command
        when /test\/functional\//, /test\/\{.*functional.*\}\//
          "Functional Tests"
        when /test\/integration\//
          "Integration Tests"
        when /test\//
          "Unit Tests"
        when /spec/
          "RSpec"
        when /cucumber/, /features/
          "Cucumber Features"
        end
      end

      def from_defined_constants
        # If the command regexps fail, let's try checking defined constants.
        if defined?(RSpec)
          "RSpec"
        elsif defined?(Test::Unit)
          "Unit Tests"
        elsif defined?(MiniTest)
          "MiniTest"
        else
          # TODO: Provide link to docs/wiki article
          warn "SimpleCov failed to recognize the test framework and/or suite used. Please specify manually using SimpleCov.command_name 'Unit Tests'."
          "Unknown Test Framework"
        end
      end
    end
  end
end
