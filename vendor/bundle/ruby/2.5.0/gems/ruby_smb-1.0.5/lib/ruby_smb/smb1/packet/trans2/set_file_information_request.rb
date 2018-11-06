module RubySMB
  module SMB1
    module Packet
      module Trans2
        # A Trans2 SET_FILE_INFORMATION Request Packet as defined in
        # [2.2.6.9.1 Request](https://msdn.microsoft.com/en-us/library/ee441527.aspx)
        class SetFileInformationRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian :little

            uint16  :fid,               label: 'FID'
            uint16  :information_level, label: 'Information Level'
            uint16  :reserved,          label: 'Reserved Space'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The Trans2 Data Block for this particular Subcommand
          class Trans2Data < BinData::Record
            include RubySMB::Fscc::FileInformation

            choice :info_level_struct, selection: -> { parent.trans2_parameters.information_level } do
              # It supports new pass-through Information Level capabilities, as specified in
              # [2.2.2.3.5 Pass-through Information Level Codes](https://msdn.microsoft.com/en-us/library/ff470158.aspx)
              file_disposition_information (FILE_DISPOSITION_INFORMATION + SMB_INFO_PASSTHROUGH), label: 'File Disposition Information'
              file_rename_information      (FILE_RENAME_INFORMATION + SMB_INFO_PASSTHROUGH),      label: 'File Rename Information'
            end

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
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::SET_FILE_INFORMATION
          end
        end
      end
    end
  end
end
