module RSpec
  module Core
    module Formatters
      # @api private
      # Formatter for providing message output as a fallback when no other
      # profiler implements #message
      class FallbackMessageFormatter
        Formatters.register self, :message

        def initialize(output)
          @output = output
        end

        # @private
        attr_reader :output

        # @api public
        #
        # Used by the reporter to send messages to the output stream.
        #
        # @param notification [MessageNotification] containing message
        def message(notification)
          output.puts notification.message
        end
      end
    end
  end
end
