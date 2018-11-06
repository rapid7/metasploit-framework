module RubySMB
  module SMB1
    module Packet
      module Trans2
        # A Trans2 FIND_NEXT2 Request Packet as defined in
        # [2.2.6.3.1 Request](https://msdn.microsoft.com/en-us/library/ee441844.aspx)
        class FindNext2Request < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian  :little

            uint16  :sid,               label: 'Search ID'
            uint16  :search_count,      label: 'Search Count'
            uint16  :information_level, label: 'Information Level'
            uint32  :resume_key,        label: 'Resume Key'

            struct :flags do
              bit3  :reserved,    label: 'Reserved Space'
              bit1  :backup,      label: 'With Backup Intent'
              bit1  :continue,    label: 'Continue From Last'
              bit1  :resume_keys, label: 'Return Resume Keys'
              bit1  :close_eos,   label: 'Close at End of Search'
              bit1  :close,       label: 'Close Search After This Request'

              bit8  :reserved2,   label: 'Reserved Space'
            end

            choice :filename, :copy_on_change => true, selection: -> { @obj.parent.parent.parent.smb_header.flags2.unicode } do
              stringz16 1, label: 'FileName'
              stringz   0, label: 'FileName'
            end

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The Trans2 Data Blcok for this particular Subcommand
          class Trans2Data < BinData::Record
            smb_gea_list :extended_attribute_list, label: 'Get Extended Attribute List',
              onlyif: -> { parent.trans2_parameters.information_level == FindInformationLevel::SMB_INFO_QUERY_EAS_FROM_LIST}

            # Returns the length of the Trans2Data struct
            # in number of bytes
            def length
              do_num_bytes
            end
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
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::FIND_NEXT2
          end
        end
      end
    end
  end
end
