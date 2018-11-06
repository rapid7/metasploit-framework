require 'rspec/core'
require 'rspec/core/formatters'

module RSpec
  module Rerun
    class Formatter
      ::RSpec::Core::Formatters.register self, :dump_failures

      FILENAME = 'rspec.failures'

      def initialize(_); end

      def dump_failures(notification)
        if notification.failed_examples.empty?
          clean!
        else
          rerun_commands = notification.failed_examples.map { |e| retry_command(e) }
          File.write(FILENAME, rerun_commands.join("\n"))
        end
      end

      def clean!
        File.delete FILENAME if File.exist? FILENAME
      end

      private

      def retry_command(example)
        if example.respond_to?(:rerun_argument)
          example.rerun_argument
        else
          example.location.gsub("\"", "\\\"")
        end
      end
    end
  end
end
