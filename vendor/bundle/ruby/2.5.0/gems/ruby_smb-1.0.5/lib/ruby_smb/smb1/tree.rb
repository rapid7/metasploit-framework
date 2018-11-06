module RubySMB
  module SMB1
    # An SMB1 connected remote Tree, as returned by a
    # [RubySMB::SMB1::Packet::TreeConnectRequest]
    class Tree
      # The client this Tree is connected through
      # @!attribute [rw] client
      #   @return [RubySMB::Client]
      attr_accessor :client

      # The current Guest Share Permissions
      # @!attribute [rw] guest_permissions
      #   @return [RubySMB::SMB1::BitField::DirectoryAccessMask]
      attr_accessor :guest_permissions

      # The current Maximal Share Permissions
      # @!attribute [rw] permissions
      #   @return [RubySMB::SMB1::BitField::DirectoryAccessMask]
      attr_accessor :permissions

      # The share path associated with this Tree
      # @!attribute [rw] share
      #   @return [String]
      attr_accessor :share

      # The Tree ID for this Tree
      # @!attribute [rw] id
      #   @return [Integer]
      attr_accessor :id

      def initialize(client:, share:, response:)
        @client             = client
        @share              = share
        @id                 = response.smb_header.tid
        @guest_permissions  = response.parameter_block.guest_access_rights
        @permissions        = response.parameter_block.access_rights
      end

      # Disconnects this Tree from the current session
      #
      # @return [WindowsError::ErrorCode] the NTStatus sent back by the server.
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a TreeDisconnectResponse packet
      def disconnect!
        request = RubySMB::SMB1::Packet::TreeDisconnectRequest.new
        request = set_header_fields(request)
        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::TreeDisconnectResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::TreeDisconnectResponse::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
        response.status_code
      end

      # Open a file on the remote share.
      #
      # @example
      #   tree = client.tree_connect("\\\\192.168.99.134\\Share")
      #   tree.open_file(filename: "myfile")
      #
      # @param filename [String] name of the file to be opened
      # @param flags [BinData::Struct, Hash] flags to setup the request (see {RubySMB::SMB1::Packet::NtCreateAndxRequest})
      # @param options [RubySMB::SMB1::BitField::CreateOptions, Hash] flags that defines how the file should be created
      # @param disposition [Integer] 32-bit field that defines how an already-existing file or a new file needs to be handled (constants are defined in {RubySMB::Dispositions})
      # @param impersonation [Integer] 32-bit field that defines the impersonation level (constants are defined in {RubySMB::ImpersonationLevels})
      # @param read [TrueClass, FalseClass] request a read access
      # @param write [TrueClass, FalseClass] request a write access
      # @param delete [TrueClass, FalseClass] request a delete access
      # @return [RubySMB::SMB1::File] handle to the created file
      # @raise [RubySMB::Error::InvalidPacket] if the response command is not SMB_COM_NT_CREATE_ANDX
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def open_file(filename:, flags: nil, options: nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                    impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE, read: true, write: false, delete: false)
        nt_create_andx_request = RubySMB::SMB1::Packet::NtCreateAndxRequest.new
        nt_create_andx_request = set_header_fields(nt_create_andx_request)

        nt_create_andx_request.parameter_block.ext_file_attributes.normal = 1

        if flags
          nt_create_andx_request.parameter_block.flags = flags
        else
          nt_create_andx_request.parameter_block.flags.request_extended_response = 1
        end

        if options
          nt_create_andx_request.parameter_block.create_options = options
        else
          nt_create_andx_request.parameter_block.create_options.directory_file     = 0
          nt_create_andx_request.parameter_block.create_options.non_directory_file = 1
        end

        if read
          nt_create_andx_request.parameter_block.share_access.share_read     = 1
          nt_create_andx_request.parameter_block.desired_access.read_data    = 1
          nt_create_andx_request.parameter_block.desired_access.read_ea      = 1
          nt_create_andx_request.parameter_block.desired_access.read_attr    = 1
          nt_create_andx_request.parameter_block.desired_access.read_control = 1
        end

        if write
          nt_create_andx_request.parameter_block.share_access.share_write   = 1
          nt_create_andx_request.parameter_block.desired_access.write_data  = 1
          nt_create_andx_request.parameter_block.desired_access.append_data = 1
          nt_create_andx_request.parameter_block.desired_access.write_ea    = 1
          nt_create_andx_request.parameter_block.desired_access.write_attr  = 1
        end

        if delete
          nt_create_andx_request.parameter_block.share_access.share_delete    = 1
          nt_create_andx_request.parameter_block.desired_access.delete_access = 1
        end

        nt_create_andx_request.parameter_block.impersonation_level = impersonation
        nt_create_andx_request.parameter_block.create_disposition  = disposition

        unicode_enabled = nt_create_andx_request.smb_header.flags2.unicode == 1
        nt_create_andx_request.data_block.file_name = add_null_termination(str: filename, unicode: unicode_enabled)

        raw_response = @client.send_recv(nt_create_andx_request)
        response = RubySMB::SMB1::Packet::NtCreateAndxResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::NtCreateAndxResponse::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end

        case response.parameter_block.resource_type 
        when RubySMB::SMB1::ResourceType::BYTE_MODE_PIPE, RubySMB::SMB1::ResourceType::MESSAGE_MODE_PIPE
          RubySMB::SMB1::Pipe.new(name: filename, tree: self, response: response)
        when RubySMB::SMB1::ResourceType::DISK
          RubySMB::SMB1::File.new(name: filename, tree: self, response: response)
        else
          raise RubySMB::Error::RubySMBError
        end
      end

      # List `directory` on the remote share.
      #
      # @example
      #   tree = client.tree_connect("\\\\192.168.99.134\\Share")
      #   tree.list(directory: "path\\to\\directory")
      #
      # @param directory [String] path to the directory to be listed
      # @param pattern [String] search pattern
      # @param type [Class] file information class
      # @return [Array] array of directory structures
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a Trans2 packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def list(directory: '\\', pattern: '*', unicode: true,
               type: RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo)
        find_first_request = RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new
        find_first_request = set_header_fields(find_first_request)
        find_first_request.smb_header.flags2.unicode  = 1 if unicode

        search_path = directory.dup
        search_path << '\\' unless search_path.end_with?('\\')
        search_path << pattern
        search_path = '\\' + search_path unless search_path.start_with?('\\')

        # Set the search parameters
        t2_params = find_first_request.data_block.trans2_parameters
        t2_params.search_attributes.hidden    = 1
        t2_params.search_attributes.system    = 1
        t2_params.search_attributes.directory = 1
        t2_params.flags.close_eos             = 1
        t2_params.flags.resume_keys           = 0
        t2_params.information_level           = type::CLASS_LEVEL
        t2_params.filename                    = search_path
        t2_params.search_count                = 10

        find_first_request = set_find_params(find_first_request)

        raw_response  = client.send_recv(find_first_request)
        response      = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans2::FindFirst2Response::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end

        results = response.results(type, unicode: unicode)

        eos   = response.data_block.trans2_parameters.eos
        sid   = response.data_block.trans2_parameters.sid
        last  = results.last.file_name

        while eos.zero?
          find_next_request = RubySMB::SMB1::Packet::Trans2::FindNext2Request.new
          find_next_request = set_header_fields(find_next_request)
          find_next_request.smb_header.flags2.unicode   = 1 if unicode

          t2_params                             = find_next_request.data_block.trans2_parameters
          t2_params.sid                         = sid
          t2_params.flags.close_eos             = 1
          t2_params.flags.resume_keys           = 0
          t2_params.information_level           = type::CLASS_LEVEL
          t2_params.filename                    = last
          t2_params.search_count                = 10

          find_next_request = set_find_params(find_next_request)

          raw_response  = client.send_recv(find_next_request)
          response      = RubySMB::SMB1::Packet::Trans2::FindNext2Response.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB1::Packet::Trans2::FindNext2Response::COMMAND,
              received_proto: response.smb_header.protocol,
              received_cmd:   response.smb_header.command
            )
          end
          unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
            raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
          end

          results += response.results(type, unicode: unicode)

          eos   = response.data_block.trans2_parameters.eos
          last  = results.last.file_name
        end

        results
      end

      # Sets a few preset header fields that will always be set the same
      # way for Tree operations. This is, the TreeID and Extended Attributes.
      #
      # @param [RubySMB::SMB::Packet] the request packet to modify
      # @return [RubySMB::SMB::Packet] the modified packet.
      def set_header_fields(request)
        request.smb_header.tid        = @id
        request.smb_header.flags2.eas = 1
        request
      end

      private

      # Sets ParameterBlock options for FIND_FIRST2 and
      # FIND_NEXT2 requests. In particular we need to do this
      # to tell the server to ignore the Trans2DataBlock as we are
      # not sending any GEA lists in this instance.
      def set_find_params(request)
        request.parameter_block.data_count             = 0
        request.parameter_block.data_offset            = 0
        request.parameter_block.total_parameter_count  = request.parameter_block.parameter_count
        request.parameter_block.max_parameter_count    = request.parameter_block.parameter_count
        request.parameter_block.max_data_count         = 16_384
        request
      end

      # Add null termination to `str` in case it is not already null-terminated.
      #
      # @str [String] the string to be null-terminated
      # @unicode [TrueClass, FalseClass] True if the null-termination should be Unicode encoded
      # @return [String] the null-terminated string
      def add_null_termination(str:, unicode: false)
        null_termination = unicode ? "\x00".encode('UTF-16LE') : "\x00"
        if str.end_with?(null_termination)
          return str
        else
          return str + null_termination
        end
      end

    end
  end
end
