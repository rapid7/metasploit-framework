module RubySMB
  module SMB2
    # Represents a file on the Remote server that we can perform
    # various I/O operations on.
    class File
      # The maximum number of byte we want to read or write
      # in a single packet.
      MAX_PACKET_SIZE = 32_768

      # The {FileAttributes} for the file
      # @!attribute [rw] attributes
      #   @return [RubySMB::Fscc::FileAttributes]
      attr_accessor :attributes

      # The {Smb2FileId} for the file
      # @!attribute [rw] guid
      #   @return [RubySMB::Field::Smb2FileId]
      attr_accessor :guid

      # The last access date/time for the file
      # @!attribute [rw] last_access
      #   @return [DateTime]
      attr_accessor :last_access

      # The last change date/time for the file
      # @!attribute [rw] last_change
      #   @return [DateTime]
      attr_accessor :last_change

      # The last write date/time for the file
      # @!attribute [rw] last_write
      #   @return [DateTime]
      attr_accessor :last_write

      # The name of the file
      # @!attribute [rw] name
      #   @return [String]
      attr_accessor :name

      # The actual size, in bytes, of the file
      # @!attribute [rw] size
      #   @return [Integer]
      attr_accessor :size

      # The size in bytes that the file occupies on disk
      # @!attribute [rw] size_on_disk
      #   @return [Integer]
      attr_accessor :size_on_disk

      # The {RubySMB::SMB2::Tree} that this file belong to
      # @!attribute [rw] tree
      #   @return [RubySMB::SMB2::Tree]
      attr_accessor :tree

      def initialize(tree:, response:, name:)
        raise ArgumentError, 'No Tree Provided' if tree.nil?
        raise ArgumentError, 'No Response Provided' if response.nil?

        @tree = tree
        @name = name

        @attributes   = response.file_attributes
        @guid         = response.file_id
        @last_access  = response.last_access.to_datetime
        @last_change  = response.last_change.to_datetime
        @last_write   = response.last_write.to_datetime
        @size         = response.end_of_file
        @size_on_disk = response.allocation_size
      end

      # Appends the supplied data to the end of the file.
      #
      # @param data [String] the data to write to the file
      # @return [WindowsError::ErrorCode] the NTStatus code returned from the operation
      def append(data:'')
        write(data: data, offset: size)
      end

      # Closes the handle to the remote file.
      #
      # @return [WindowsError::ErrorCode] the NTStatus code returned by the operation
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a CloseResponse packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def close
        close_request = set_header_fields(RubySMB::SMB2::Packet::CloseRequest.new)
        raw_response  = tree.client.send_recv(close_request)
        response = RubySMB::SMB2::Packet::CloseResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::CloseResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        response.status_code
      end

      # Read from the file, a specific number of bytes
      # from a specific offset. If no parameters are given
      # it will read the entire file.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [String] the data read from the file
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a ReadResponse packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def read(bytes: size, offset: 0)
        atomic_read_size = if bytes > tree.client.server_max_read_size
                             tree.client.server_max_read_size
                           else
                             bytes
                           end

        read_request = read_packet(read_length: atomic_read_size, offset: offset)
        raw_response = tree.client.send_recv(read_request)
        response     = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::ReadResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end

        data = response.buffer.to_binary_s

        remaining_bytes = bytes - atomic_read_size

        while remaining_bytes > 0
          offset += atomic_read_size
          atomic_read_size = remaining_bytes if remaining_bytes < tree.client.server_max_read_size

          read_request = read_packet(read_length: atomic_read_size, offset: offset)
          raw_response = tree.client.send_recv(read_request)
          response     = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB2::Packet::ReadResponse::COMMAND,
              received_proto: response.smb2_header.protocol,
              received_cmd:   response.smb2_header.command
            )
          end
          unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
            raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
          end

          data << response.buffer.to_binary_s
          remaining_bytes -= atomic_read_size
        end
        data
      end

      # Crafts the ReadRequest packet to be sent for read operations.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [RubySMB::SMB2::Packet::ReadRequest] the data read from the file
      def read_packet(read_length: 0, offset: 0)
        read_request = set_header_fields(RubySMB::SMB2::Packet::ReadRequest.new)
        read_request.read_length  = read_length
        read_request.offset       = offset
        read_request
      end
      
      def send_recv_read(read_length: 0, offset: 0)
        read_request = read_packet(read_length: read_length, offset: offset)
        raw_response = tree.client.send_recv(read_request)
        response = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::ReadResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        if response.status_code == WindowsError::NTStatus::STATUS_PENDING
          sleep 1
          raw_response = tree.client.dispatcher.recv_packet
          response = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB2::Packet::ReadResponse::COMMAND,
              received_proto: response.smb2_header.protocol,
              received_cmd:   response.smb2_header.command
            )
          end
        elsif response.status_code != WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        response.buffer.to_binary_s
      end

      # Delete a file on close
      #
      # @return [WindowsError::ErrorCode] the NTStatus Response code
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a SetInfoResponse packet
      def delete
        raw_response = tree.client.send_recv(delete_packet)
        response = RubySMB::SMB2::Packet::SetInfoResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::SetInfoResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        response.smb2_header.nt_status.to_nt_status
      end

      # Crafts the SetInfoRequest packet to be sent for delete operations.
      #
      # @return [RubySMB::SMB2::Packet::SetInfoRequest] the set info packet
      def delete_packet
        delete_request                       = set_header_fields(RubySMB::SMB2::Packet::SetInfoRequest.new)
        delete_request.file_info_class       = RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION
        delete_request.buffer.delete_pending = 1
        delete_request
      end

      # Sets the header fields that we have to set on every packet
      # we send for File operations.
      # @param request [RubySMB::GenericPacket] the request packet to set fields on
      # @return  [RubySMB::GenericPacket] the rmodified request packet
      def set_header_fields(request)
        request         = tree.set_header_fields(request)
        request.file_id = guid
        request
      end

      # Write the supplied data to the file at the given offset.
      #
      # @param data [String] the data to write to the file
      # @param offset [Integer] the offset in the file to start writing from
      # @return [WindowsError::ErrorCode] the NTStatus code returned from the operation
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a WriteResponse packet
      def write(data:'', offset: 0)
        buffer            = data.dup
        bytes             = data.length
        atomic_write_size = if bytes > tree.client.server_max_write_size
                              tree.client.server_max_write_size
                            else
                             bytes
                            end

        while buffer.length > 0 do
          write_request = write_packet(data: buffer.slice!(0,atomic_write_size), offset: offset)
          raw_response  = tree.client.send_recv(write_request)
          response      = RubySMB::SMB2::Packet::WriteResponse.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB2::Packet::WriteResponse::COMMAND,
              received_proto: response.smb2_header.protocol,
              received_cmd:   response.smb2_header.command
            )
          end
          status        = response.smb2_header.nt_status.to_nt_status

          offset+= atomic_write_size
          return status unless status == WindowsError::NTStatus::STATUS_SUCCESS
        end

        status
      end

      # Creates the Request packet for the #write command
      #
      # @param data [String] the data to write to the file
      # @param offset [Integer] the offset in the file to start writing from
      # @return []RubySMB::SMB2::Packet::WriteRequest] the request packet
      def write_packet(data:'', offset: 0)
        write_request               = set_header_fields(RubySMB::SMB2::Packet::WriteRequest.new)
        write_request.write_offset  = offset
        write_request.buffer        = data
        write_request
      end
      
      def send_recv_write(data:'', offset: 0)
        pkt = write_packet(data: data, offset: offset)
        raw_response = tree.client.send_recv(pkt)
        response = RubySMB::SMB2::Packet::WriteResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::WriteResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        if response.status_code == WindowsError::NTStatus::STATUS_PENDING
          sleep 1
          raw_response = tree.client.dispatcher.recv_packet
          response = RubySMB::SMB2::Packet::WriteResponse.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB2::Packet::WriteResponse::COMMAND,
              received_proto: response.smb2_header.protocol,
              received_cmd:   response.smb2_header.command
            )
          end
        elsif response.status_code != WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        response.write_count
      end
      
      # Rename a file
      #
      # @param new_file_name [String] the new name
      # @return [WindowsError::ErrorCode] the NTStatus Response code
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a SetInfoResponse packet
      def rename(new_file_name)
        raw_response = tree.client.send_recv(rename_packet(new_file_name))
        response = RubySMB::SMB2::Packet::SetInfoResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::SetInfoResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
        response.smb2_header.nt_status.to_nt_status
      end

      # Crafts the SetInfoRequest packet to be sent for rename operations.
      #
      # @param new_file_name [String] the new name
      # @return [RubySMB::SMB2::Packet::SetInfoRequest] the set info packet
      def rename_packet(new_file_name)
        rename_request                  = set_header_fields(RubySMB::SMB2::Packet::SetInfoRequest.new)
        rename_request.file_info_class  = RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION
        rename_request.buffer.file_name = new_file_name.encode('utf-16le')
        rename_request
      end

    end
  end
end
