module RubySMB
  module SMB1
    module Packet
      # A SMB1 TreeConnect Response Packet as defined in
      # [2.2.4.7.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246331.aspx)
      class TreeConnectResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT

        # A SMB1 Parameter Block as defined by the {SessionSetupResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block                :andx_block
          optional_support           :optional_support
          directory_access_mask      :access_rights,       label: 'Maximal Share Access Rights', onlyif: -> { word_count >= 5 }
          directory_access_mask      :guest_access_rights, label: 'Guest Share Access Rights',   onlyif: -> { word_count == 7 }
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          stringz   :service,             label: 'Service Type'
          stringz   :native_file_system,  label: 'Native File System'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end

        # Returns the ACCESS_MASK for the Maximal Share Access Rights. The packet
        # defaults this to a {RubySMB::SMB1::BitField::DirectoryAccessMask}. If it is anything other than
        # a directory that has been connected to, it will re-cast it as a {}RubySMB::SMB1::BitField::FileAccessMask}
        #
        # @return [RubySMB::SMB1::BitField::DirectoryAccessMask] if a directory was connected to
        # @return [RubySMB::SMB1::BitField::FileAccessMask] if anything else was connected to
        # @raise [RubySMB::Error::InvalidBitField] if ACCESS_MASK bit field is not valid
        def access_rights
          if is_directory?
            parameter_block.access_rights
          else
            mask = parameter_block.access_rights.to_binary_s
            begin
              RubySMB::SMB1::BitField::FileAccessMask.read(mask)
            rescue IOError
              raise RubySMB::Error::InvalidBitField, 'Invalid ACCESS_MASK for the Maximal Share Access Rights'
            end
          end
        end

        # Returns the ACCESS_MASK for the Guest Share Access Rights. The packet
        # defaults this to a {RubySMB::SMB1::BitField::DirectoryAccessMask}. If it is anything other than
        # a directory that has been connected to, it will re-cast it as a {RubySMB::SMB1::BitField::FileAccessMask}
        #
        # @return [RubySMB::SMB1::BitField::DirectoryAccessMask] if a directory was connected to
        # @return [RubySMB::SMB1::BitField::FileAccessMask] if anything else was connected to
        def guest_access_rights
          if is_directory?
            parameter_block.guest_access_rights
          else
            mask = parameter_block.guest_access_rights.to_binary_s
            begin
              RubySMB::SMB1::BitField::FileAccessMask.read(mask)
            rescue IOError
              raise RubySMB::Error::InvalidBitField, 'Invalid ACCESS_MASK for the Guest Share Access Rights'
            end
          end
        end

        # Checks whether the response is for a Directory
        # This alters the type of access mask that is used.
        #
        # @return [TrueClass] if service is 'A:'
        # @return [FalseClass] if service is NOT 'A:'
        def is_directory?
          data_block.service == 'A:'
        end
      end
    end
  end
end
