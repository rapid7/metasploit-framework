require 'winrm'

module Net
  module MsfWinRM
    # For parsing of output streams (stdout, stderr); subclassed
    # so MSF can manage retry loops itself
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
        resp_doc = nil
        until command_done?(resp_doc, wait_for_done_state)
          logger.debug('[WinRM] Waiting for output...')
          resp_doc = send_get_output_message(wsmv_message.build)
          logger.debug('[WinRM] Processing output')
          read_streams(resp_doc) do |stream|
            yield stream, resp_doc
          end
        end

        if command_done?(resp_doc, true)
          raise EOFError, 'Program terminated'
        end
      end
    end
  end
end
