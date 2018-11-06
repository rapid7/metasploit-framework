module RubySMB
  module SMB1
    module Packet
      module Trans2
        # This class represents an SMB1 Trans2 FIND_NEXT2 Response Packet as defined in
        # [2.2.6.3.2 Response](https://msdn.microsoft.com/en-us/library/ee441871.aspx)
        class FindNext2Response < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          # The Trans2 Parameter Block for this particular Subcommand
          class Trans2Parameters < BinData::Record
            endian  :little

            uint16  :search_count,      label: 'Search Count'
            uint16  :eos,               label: 'End of Search'
            uint16  :ea_error_offset,   label: 'Offset to EA Error'
            uint16  :last_name_offset,  label: 'Last Name Offset'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The Trans2 Data Block for this particular Subcommand
          class Trans2Data < BinData::Record
            rest :buffer, label: 'Results Buffer'

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
            trans2_data        :trans2_data,        label: 'Trans2 Data', length: 0
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::FIND_NEXT2
            smb_header.flags.reply = 1
          end

          # Returns the File Information in an array of appropriate
          # structs for the given FileInformationClass. Pulled out of
          # the string buffer.
          #
          # @param klass [Class] the FileInformationClass class to read the data as
          # @return [array<BinData::Record>] An array of structs holding the requested information
          # @raise [RubySMB::Error::InvalidPacket] if the string buffer is not a valid File Information packet
          def results(klass, unicode:)
            information_classes = []
            blob = data_block.trans2_data.buffer.to_binary_s.dup
            until blob.empty?
              length = blob[0, 4].unpack('V').first

              data = if length.zero?
                       blob.slice!(0, blob.length)
                     else
                       blob.slice!(0, length)
                     end

              file_info = klass.new
              file_info.unicode = unicode
              begin
                information_classes << file_info.read(data)
              rescue IOError
                raise RubySMB::Error::InvalidPacket, "Invalid #{klass} File Information packet in the string buffer"
              end
            end
            information_classes
          end
        end
      end
    end
  end
end
