module RubySMB
  module SMB1
    # Represents a pipe on the Remote server that we can perform
    # various I/O operations on.
    class Pipe < File
      require 'ruby_smb/smb1/dcerpc'

      include RubySMB::SMB1::Dcerpc

      # Reference: https://msdn.microsoft.com/en-us/library/ee441883.aspx
      STATUS_DISCONNECTED = 0x0001
      STATUS_LISTENING    = 0x0002
      STATUS_OK           = 0x0003
      STATUS_CLOSED       = 0x0004

      # Performs a peek operation on the named pipe
      #
      # @param peek_size [Integer] Amount of data to peek
      # @return [RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse]
      # @raise [RubySMB::Error::InvalidPacket] If not a valid PeekNmpipeResponse
      # @raise [RubySMB::Error::UnexpectedStatusCode] If status is not STATUS_BUFFER_OVERFLOW or STATUS_SUCCESS
      def peek(peek_size: 0)
        packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest.new
        packet.fid = @fid
        packet.parameter_block.max_data_count = peek_size
        packet = @tree.set_header_fields(packet)
        raw_response = @tree.client.send_recv(packet)
        response = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end

        unless response.status_code == WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW or response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end

        response
      end

      # @return [Integer] The number of bytes available to be read from the pipe
      def peek_available
        packet = peek
        # Only 1 of these should be non-zero
        packet.data_block.trans_parameters.read_data_available or packet.data_block.trans_parameters.message_bytes_length
      end

      # @return [Integer] Pipe status
      def peek_state
        packet = peek
        packet.data_block.trans_parameters.pipe_state
      end

      # @return [Boolean] True if pipe is connected, false otherwise
      def is_connected?
        begin
          state = peek_state
        rescue RubySMB::Error::UnexpectedStatusCode => e
          if e.message == 'STATUS_INVALID_HANDLE'
            return false
          end
          raise e
        end
        state == STATUS_OK
      end

    end
  end
end
