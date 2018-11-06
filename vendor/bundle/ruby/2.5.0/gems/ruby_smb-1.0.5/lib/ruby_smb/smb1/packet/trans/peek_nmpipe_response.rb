module RubySMB
  module SMB1
    module Packet
      module Trans
        # This class represents an SMB1 Trans PeekNamedPipe Response Packet as defined in
        # [2.2.5.5.2 Response](https://msdn.microsoft.com/en-us/library/ee441883.aspx)
        class PeekNmpipeResponse < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION

          class ParameterBlock < RubySMB::SMB1::Packet::Trans::Response::ParameterBlock
          end

          # The Trans Parameter Block for this particular Subcommand
          class TransParameters < BinData::Record
            endian :little

            uint16 :read_data_available,     label: 'Read bytes available'
            uint16 :message_bytes_length,    label: 'Byte length of available message'
            uint16 :pipe_state,              label: 'Named pipe state'

            # Returns the length of the TransParameters struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          class TransData < BinData::Record
            string :read_data, label: 'Readable data', length: -> { parent.parameter_block.total_data_count }

            # Returns the length of the TransData struct
            # in number of bytes
            def length
              do_num_bytes
            end
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            string           :pad1,               length: -> { pad1_length }
            trans_parameters :trans_parameters,   label: 'Trans Parameters'
            # dont understand the padding on this one...
            string           :pad2,               length: -> { parent.parameter_block.data_offset - parent.parameter_block.parameter_offset - parent.parameter_block.parameter_count }
            trans_data       :trans_data,         label: 'Trans Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            smb_header.flags.reply = 1
            parameter_block.setup << RubySMB::SMB1::Packet::Trans::Subcommands::PEEK_NMPIPE
          end
        end
      end
    end
  end
end
