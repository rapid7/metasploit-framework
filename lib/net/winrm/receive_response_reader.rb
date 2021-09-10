require 'winrm'

module Net
  module MsfWinRM
    class ReceiveResponseReader < WinRM::WSMV::ReceiveResponseReader
      def send_get_output_message(message)
        # Overridden without retry loop
        @transport.send_request(message)
      end

      # Reads streams sent in one or more receive response messages
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @param wait_for_done_state whether to poll for a CommandState of Done
      # @yieldparam [Hash] Hash representation of stream with type and text
      # @yieldparam [REXML::Document] Complete SOAP envelope returned to wsmv_message
      # rubocop:disable Style/OptionalBooleanParameter - want to keep same signature as base class
      def read_response(wsmv_message, wait_for_done_state = false)
        # rubocop:enable Style/OptionalBooleanParameter
        response = nil

        super(wsmv_message, wait_for_done_state) do |stream, resp_doc|
          response = resp_doc
          yield stream, resp_doc
        end
        if command_done?(response, true)
          raise EOFError, 'Program terminated'
        end
      end
    end
  end
end
