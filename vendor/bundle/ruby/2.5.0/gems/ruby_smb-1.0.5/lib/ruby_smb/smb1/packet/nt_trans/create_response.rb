module RubySMB
  module SMB1
    module Packet
      module NtTrans
        # Class representing a NT Transaction Create response packet as defined in
        # [2.2.7.1.2 Response](https://msdn.microsoft.com/en-us/library/ee441961.aspx)
        class CreateResponse < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT

          class ParameterBlock < RubySMB::SMB1::Packet::NtTrans::Response::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian :little

            uint8                     :oplock_level,        label: 'OpLock Level'
            uint8                     :reserved,            label: 'Reserved Space'
            uint16                    :fid,                 label: 'File ID'
            uint32                    :create_action,       label: 'Create Action'
            uint32                    :ea_error_offset,     label: 'EA Error Offset'
            file_time                 :creation_time,       label: 'File Creation Time'
            file_time                 :last_access_time,    label: 'File Last Accessed Time'
            file_time                 :last_write_time,     label: 'File last Write Time'
            file_time                 :last_change_time,    label: 'File Last Changed Time'
            smb_ext_file_attributes   :ext_file_attributes, label: 'File Extended Attributes'
            uint64                    :allocation_size,     label: 'Allocation Size'
            uint64                    :end_of_file,         label: 'Offset to EOF'
            uint16                    :resource_type,       label: 'Resource Type'
            smb_nmpipe_status         :nmpipe_status,       label: 'Named Pipe Status'
            uint8                     :directory,           label: 'Directory'

            # Returns the length of the Trans2Parameters struct
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
            string            :trans2_data,        label: 'Trans2 Data', length: 0
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
end
