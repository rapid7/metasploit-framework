module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NT_CREATE_ANDX Request Packet as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx) and
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class NtCreateAndxRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX

        # A SMB1 Parameter Block as defined by the {NtCreateAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          and_x_block                        :andx_block
          uint8                              :reserved,            label: 'Reserved'
          uint16                             :name_length,         label: 'Name Length(bytes)', value: -> { parent.data_block.file_name.length }

          struct :flags, label: 'Flags' do
            bit3    :reserved,                   label: 'Reserved Space'
            bit1    :request_extended_response,  label: 'Request Extended Response'
            bit1    :open_target_dir,            label: 'Open Target Directory'
            bit1    :request_opbatch,            label: 'Request Batch OpLock'
            bit1    :request_oplock,             label: 'Request OpLock'
            bit1    :reserved2,                  label: 'Reserved Space'
            # Byte boundary
            bit8    :reserved3,                  label: 'Reserved Space'
            bit8    :reserved4,                  label: 'Reserved Space'
            bit8    :reserved5,                  label: 'Reserved Space'
          end

          uint32                             :root_directory_fid, label: 'Root Directory FID'

          choice :desired_access, selection: -> { ext_file_attributes.directory } do
            file_access_mask      0, label: 'Desired Access'
            directory_access_mask 1, label: 'Desired Access'
          end

          uint64                             :allocation_size,     label: 'Allocation Size'
          smb_ext_file_attributes            :ext_file_attributes, label: 'Extented File Attributes'
          share_access                       :share_access,        label: 'Share Access'
          # The following constants are defined in RubySMB::Dispositions
          uint32                             :create_disposition,  label: 'Create Disposition'
          create_options                     :create_options,      label: 'Create Options'
          # The following constants are defined in RubySMB::ImpersonationLevels
          uint32                             :impersonation_level, label: 'Impersonation Level'
          security_flags                     :security_flags,      label: 'Security Flags'
        end

        # Represents the specific layout of the DataBlock for a {NtCreateAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          string :file_name, label: 'File Name'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

      end
    end
  end
end
