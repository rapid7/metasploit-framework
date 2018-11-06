module RubySMB
  class Client
    # Contains the methods for doing ECHO commands
    module Echo
      # Sends an ECHO request packet and returns the
      # last response packet.
      #
      # @param echo [Integer] the number of times the server should echo (ignored in SMB2)
      # @param data [String] the data the server should echo back (ignored in SMB2)
      # @return [RubySMB::SMB1::Packet::EchoResponse] the last Echo Response packet received
      def smb1_echo(count: 1, data: '')
        request = RubySMB::SMB1::Packet::EchoRequest.new
        request.parameter_block.echo_count = count
        request.data_block.data = data
        raw_response = send_recv(request)
        (count - 1).times do
          raw_response = dispatcher.recv_packet
        end
        response = RubySMB::SMB1::Packet::EchoResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::EchoResponse::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
        response
      end

      # Sends an ECHO request packet and returns the
      # response packet.
      #
      # @return [RubySMB::SMB2::Packet::EchoResponse]
      def smb2_echo
        request      = RubySMB::SMB2::Packet::EchoRequest.new
        raw_response = send_recv(request)
        response = RubySMB::SMB2::Packet::EchoResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::EchoResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        response
      end
    end
  end
end
