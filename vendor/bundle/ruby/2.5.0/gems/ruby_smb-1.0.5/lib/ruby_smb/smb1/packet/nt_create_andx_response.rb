module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NT_CREATE_ANDX Response Packet as defined in
      # [2.2.4.64.2 Response](https://msdn.microsoft.com/en-us/library/ee441612.aspx) and
      # [2.2.4.9.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246334.aspx)
      class NtCreateAndxResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX

        # A SMB1 Parameter Block as defined by the {NtCreateAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          and_x_block             :andx_block
          # Constants defined in RubySMB::SMB1::OplockLevels
          uint8                   :oplock_level,        label: 'OpLock Level'
          uint16                  :fid,                 label: 'FID'
          # Constants defined in RubySMB::Dispositions
          uint32                  :create_disposition,  label: 'Create Disposition'
          file_time               :create_time,         label: 'Create Time'
          file_time               :last_access_time,    label: 'Last Access Time'
          file_time               :last_write_time,     label: 'Last Write Time'
          file_time               :last_change_time,    label: 'Last Change Time'
          smb_ext_file_attributes :ext_file_attributes, label: 'Extented File Attributes'
          uint64                  :allocation_size,     label: 'Allocation Size'
          uint64                  :end_of_file,         label: 'End of File Offset'
          # Constants defined in RubySMB::SMB1::ResourceType
          uint16                  :resource_type,       label: 'Resource Type'

          choice :status_flags, selection: -> { resource_type } do
            smb_nmpipe_status RubySMB::SMB1::ResourceType::BYTE_MODE_PIPE,    label: 'Status Flags'
            smb_nmpipe_status RubySMB::SMB1::ResourceType::MESSAGE_MODE_PIPE, label: 'Status Flags'
            file_status_flags RubySMB::SMB1::ResourceType::DISK,              label: 'Status Flags'
            uint16            :default,                                       label: 'Status Flags'
          end

          uint8                   :directory,           label: 'Directory'
          string                  :volume_guid,         label: 'Volume GUID', length: 16
          uint64                  :file_id,             label: 'File ID'

          choice :maximal_access_rights, selection: -> { ext_file_attributes.directory } do
            file_access_mask      0, label: 'Maximal Access Rights'
            directory_access_mask 1, label: 'Maximal Access Rights'
          end

          choice :guest_maximal_access_rights, selection: -> { ext_file_attributes.directory } do
            file_access_mask      0, label: 'Guest Maximal Access Rights'
            directory_access_mask 1, label: 'Guest Maximal Access Rights'
          end
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end
      end
    end
  end
end
