module RubySMB
  module SMB1
    module Packet
      module Trans2
        # This class represents an SMB1 Trans2 Open2 Response Packet as defined in
        # [2.2.6.1.2 Response](https://msdn.microsoft.com/en-us/library/ee441545.aspx)
        class Open2Response < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian :little
            uint8               :fid,             label: 'File ID'
            smb_file_attributes :file_attributes, label: 'File Attributes'
            utime               :creation_time,   label: 'Creation Time'
            open2_access_mode   :access_mode,     label: 'AccessMode'
            uint16              :resource_type,   label: 'Resource Type'
            smb_nmpipe_status   :nmpipe_status,   label: 'Named Pipe Status'

            struct :action_taken do
              endian  :little
              bit6    :reserved,    label: 'Reserved Space'
              bit2    :open_result, label: 'Open Result'
              # byte boundary
              bit1    :lock_status, label: 'Lock Status'
              resume_byte_alignment
            end

            uint32  :reserved,                      label: 'Reserved Space'
            uint16  :extended_attribute_offset,     label: 'Extended Attribute Offset'
            uint32  :extended_attribute_length,     label: 'Extended Attribute Length'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            string             :pad1,               length: -> { pad1_length }
            trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
            string             :pad2,               length: -> { pad2_length }
            string             :trans2_data,        label: 'Trans2 Data', length: 0
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::OPEN2
            smb_header.flags.reply = 1
          end
        end
      end
    end
  end
end
