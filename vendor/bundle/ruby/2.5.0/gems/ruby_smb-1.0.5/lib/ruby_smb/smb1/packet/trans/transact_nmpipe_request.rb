module RubySMB
  module SMB1
    module Packet
      module Trans

        # A Trans TRANSACT_NMPIPE Request Packet as defined in
        # [2.2.5.6.1 Request](https://msdn.microsoft.com/en-us/library/ee441832.aspx)
        class TransactNmpipeRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION

          class ParameterBlock < RubySMB::SMB1::Packet::Trans::Request::ParameterBlock
          end

          class TransData < BinData::Record
            string  :write_data, label: 'Write Data', read_length: -> { parent.parent.parameter_block.data_count }

            # Returns the length of the TransData struct in number of bytes
            def length
              do_num_bytes
            end
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            # If unicode is set, the name field must be aligned to start on a 2-byte
            # boundary from the start of the SMB header:
            string :pad_name, length: -> { pad_name_length },
                              onlyif: -> { parent.smb_header.flags2.unicode.to_i == 1 }
            choice :name, :selection      => lambda { parent.smb_header.flags2.unicode.to_i },
                          :copy_on_change => true do
              stringz   0, label: 'Name', initial_value: "\\PIPE\\"
              stringz16 1, label: 'Name', initial_value: "\\PIPE\\".encode('utf-16le')
            end
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
            parameter_block.max_parameter_count = 0x0000
            parameter_block.max_setup_count = 0x00
            parameter_block.setup << RubySMB::SMB1::Packet::Trans::Subcommands::TRANSACT_NMPIPE
            # FID: must be set to a valid FID from a server response for a
            # previous SMB command to open or create a named pipe.
            parameter_block.setup << 0x0000
          end

          def set_fid(fid)
            parameter_block.setup[1] = fid
          end
        end
      end
    end
  end
end
