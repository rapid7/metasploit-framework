RSpec::Support.require_rspec_core "formatters/helpers"
require 'stringio'

module RSpec
  module Core
    module Formatters
      # RSpec's built-in formatters are all subclasses of
      # RSpec::Core::Formatters::BaseFormatter.
      #
      # @see RSpec::Core::Formatters::BaseTextFormatter
      # @see RSpec::Core::Reporter
      # @see RSpec::Core::Formatters::Protocol
      class BaseFormatter
        # All formatters inheriting from this formatter will receive these
        # notifications.
        Formatters.register self, :start, :example_group_started, :close
        attr_accessor :example_group
        attr_reader :output

        # @api public
        # @param output [IO] the formatter output
        # @see RSpec::Core::Formatters::Protocol#initialize
        def initialize(output)
          @output = output || StringIO.new
          @example_group = nil
        end

        # @api public
        #
        # @param notification [StartNotification]
        # @see RSpec::Core::Formatters::Protocol#start
        def start(notification)
          start_sync_output
          @example_count = notification.count
        end

        # @api public
        #
        # @param notification [GroupNotification] containing example_group
        #   subclass of `RSpec::Core::ExampleGroup`
        # @see RSpec::Core::Formatters::Protocol#example_group_started
        def example_group_started(notification)
          @example_group = notification.group
        end

        # @api public
        #
        # @param _notification [NullNotification] (Ignored)
        # @see RSpec::Core::Formatters::Protocol#close
        def close(_notification)
          restore_sync_output
        end

      private

        def start_sync_output
          @old_sync, output.sync = output.sync, true if output_supports_sync
        end

        def restore_sync_output
          output.sync = @old_sync if output_supports_sync && !output.closed?
        end

        def output_supports_sync
          output.respond_to?(:sync=)
        end
      end
    end
  end
end
