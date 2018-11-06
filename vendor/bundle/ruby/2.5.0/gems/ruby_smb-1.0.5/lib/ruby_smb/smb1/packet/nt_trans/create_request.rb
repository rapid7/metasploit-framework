module RubySMB
  module SMB1
    module Packet
      module NtTrans
        # Class representing a generic NT Transaction request packet as defined in
        # [2.2.4.62.1 Request](https://msdn.microsoft.com/en-us/library/ee441534.aspx)
        class CreateRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT

          class ParameterBlock < RubySMB::SMB1::Packet::NtTrans::Request::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian :little

            struct :flags do
              bit4  :reserved
              bit1  :open_target_dir, label: 'Open Parent Directory'
              bit1  :request_opbatch, label: 'Request Batch OpLock'
              bit1  :request_oplock,  label: 'Request Exclusive OpLock'
              bit1  :reserved2,       label: 'Reserved Space'
              # byte boundary
              bit8  :reserved3,       label: 'Reserved Space'
              bit8  :reserved4,       label: 'Reserved Space'
              bit8  :reserved5,       label: 'Reserved Space'
            end

            uint32                  :root_directory_fid, label: 'Root Directory FID'

            choice :desired_access, selection: -> { ext_file_attribute.directory } do
              file_access_mask      0, label: 'Desired Access'
              directory_access_mask 1, label: 'Desired Access'
            end

            uint64                  :allocation_size, label: 'Allocation Size'
            smb_ext_file_attributes :ext_file_attribute
            share_access            :share_access,                label: 'Share Access'
            uint32                  :create_disposition,          label: 'Create Disposition'
            create_options          :create_options
            uint32                  :security_descriptor_length,  label: 'Security Descriptor Length',  initial_value: -> { parent.trans2_data.security_descriptor.length }
            uint32                  :ea_length,                   label: 'Extended Attributes Length',  initial_value: -> { parent.trans2_data.extended_attributes.length }
            uint32                  :impersonation_level,         label: 'Impersonation Level'

            struct :security_flags do
              bit6  :reserved,          label: 'Reserved Space'
              bit1  :effective_only,    label: 'Effective Only'
              bit1  :context_tracking,  label: 'Context Tracking'
            end

            string :name, label: 'File Name'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The Trans2 Data Blcok for this particular Subcommand
          class Trans2Data < BinData::Record
            security_descriptor :security_descriptor
            file_full_ea_info   :extended_attributes

            # Returns the length of the Trans2Data struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            string            :pad1,               length: -> { pad1_length }
            trans2_parameters :trans2_parameters,  label: 'Trans2 Parameters'
            string            :pad2,               length: -> { pad2_length }
            trans2_data       :trans2_data,        label: 'Trans2 Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            parameter_block.function = RubySMB::SMB1::Packet::NtTrans::Subcommands::CREATE
          end
        end
      end
    end
  end
end
