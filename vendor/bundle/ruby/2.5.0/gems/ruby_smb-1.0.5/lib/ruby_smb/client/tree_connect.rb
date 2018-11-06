module RubySMB
  class Client
    # This module contains all of the methods for a client to connect to a
    # remote share or named pipe.
    module TreeConnect
      #
      # SMB 1 Methods
      #

      # Sends a request to connect to a remote Tree and returns the
      # {RubySMB::SMB1::Tree}
      #
      # @param share [String] the share path to connect to
      # @return [RubySMB::SMB1::Tree] the connected Tree
      def smb1_tree_connect(share)
        request = RubySMB::SMB1::Packet::TreeConnectRequest.new
        request.smb_header.tid = 65_535
        request.data_block.path = share
        raw_response = send_recv(request)
        response = RubySMB::SMB1::Packet::TreeConnectResponse.read(raw_response)
        smb1_tree_from_response(share, response)
      end

      # Parses a Tree structure from a Tree Connect Response
      #
      # @param share [String] the share path to connect to
      # @param response [RubySMB::SMB1::Packet::TreeConnectResponse] the response packet to parse into our Tree
      # @return [RubySMB::SMB1::Tree]
      # @raise [RubySMB::Error::InvalidPacket] if the response command is not a TreeConnectResponse packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response status code is not STATUS_SUCCESS
      def smb1_tree_from_response(share, response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::TreeConnectResponse::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        RubySMB::SMB1::Tree.new(client: self, share: share, response: response)
      end

      #
      # SMB 2 Methods
      #

      # Sends a request to connect to a remote Tree and returns the
      # {RubySMB::SMB2::Tree}
      #
      # @param share [String] the share path to connect to
      # @return [RubySMB::SMB2::Tree] the connected Tree
      def smb2_tree_connect(share)
        request = RubySMB::SMB2::Packet::TreeConnectRequest.new
        request.smb2_header.tree_id = 65_535
        request.encode_path(share)
        raw_response = send_recv(request)
        response = RubySMB::SMB2::Packet::TreeConnectResponse.read(raw_response)
        smb2_tree_from_response(share, response)
      end

      # Parses a Tree structure from a Tree Connect Response
      #
      # @param share [String] the share path to connect to
      # @param response [RubySMB::SMB2::Packet::TreeConnectResponse] the response packet to parse into our Tree
      # @return [RubySMB::SMB2::Tree]
      # @raise [RubySMB::Error::InvalidPacket] if the response command is not a TreeConnectResponse packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response status code is not STATUS_SUCCESS
      def smb2_tree_from_response(share, response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::TreeConnectResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        RubySMB::SMB2::Tree.new(client: self, share: share, response: response)
      end
    end
  end
end
