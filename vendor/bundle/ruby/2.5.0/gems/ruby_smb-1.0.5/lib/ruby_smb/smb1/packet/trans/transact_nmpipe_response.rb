module RubySMB
  module SMB1
    module Packet
      module Trans

        # A Trans TRANSACT_NMPIPE Response Packet as defined in
        # [2.2.5.6.2 Response](https://msdn.microsoft.com/en-us/library/ee442003.aspx)
        class TransactNmpipeResponse < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION

          class ParameterBlock < RubySMB::SMB1::Packet::Trans::Response::ParameterBlock
          end

          class TransData < BinData::Record
            string :read_data, label: 'Read Data', read_length: -> { parent.parameter_block.data_count }

            # Returns the length of the TransData struct in number of bytes
            def length
              do_num_bytes
            end
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            string     :pad1,             length: lambda { pad1_length }
            string     :trans_parameters, label: 'Trans Parameters', read_length: -> { parent.parameter_block.parameter_count }
            string     :pad2,             length: lambda { pad2_length }
            trans_data :trans_data,       label: 'Trans Data'
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
