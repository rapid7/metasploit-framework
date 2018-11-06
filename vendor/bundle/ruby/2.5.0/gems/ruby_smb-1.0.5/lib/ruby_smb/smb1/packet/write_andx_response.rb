module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_WRITE_ANDX Response Packet as defined in
      # [2.2.4.43.2 Response](https://msdn.microsoft.com/en-us/library/ee441673.aspx)
      # [2.2.4.3.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/ff469858.aspx)
      class WriteAndxResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_WRITE_ANDX

        # A SMB1 Parameter Block as defined by the {WriteAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian      :little

          and_x_block :andx_block
          uint16      :count_low,  label: 'Count Low'
          uint16      :available,  label: 'Available'
          uint16      :count_high, label: 'Count High'
          uint16      :reserved,   label: 'Reserved'
        end

        # Represents the specific layout of the DataBlock for a {WriteAndxResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
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
