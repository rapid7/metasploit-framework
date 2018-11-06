module RubySMB
  module SMB1
    module Packet
      module Trans2
        # A Trans2 OPEN2 Request Packet as defined in
        # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
        class Open2Request < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian :little
            open2_flags         :flags,           label: 'Flags'
            open2_access_mode   :access_mode,     label: 'AccessMode'
            uint16              :reserved,        label: 'Reserved Space'
            smb_file_attributes :file_attributes, label: 'File Attributes'
            utime               :creation_time,   label: 'Creation Time'
            open2_open_mode     :open_mode,       label: 'Open Mode'
            uint32              :allocation_size, label: 'Allocation Size'
            array               :reserved2, initial_length: 5 do
              uint16 initial_value: 0x0000
            end
            stringz :filename, label: 'Filename'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The Trans2 Data Blcok for this particular Subcommand
          class Trans2Data < BinData::Record
            smb_fea_list :extended_attribute_list, label: 'Extended Attribute List'
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            uint8              :name,               label: 'Name', initial_value: 0x00
            string             :pad1,               length: -> { pad1_length }
            trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
            string             :pad2,               length: -> { pad2_length }
            trans2_data        :trans2_data,        label: 'Trans2 Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::OPEN2
          end
        end
      end
    end
  end
end
