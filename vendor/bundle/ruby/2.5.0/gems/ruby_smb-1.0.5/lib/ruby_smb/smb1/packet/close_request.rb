module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_CLOSE Request Packet as defined in
      # [2.2.4.5.1 Request](https://msdn.microsoft.com/en-us/library/ee442151.aspx)
      class CloseRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_CLOSE

        # A SMB1 Parameter Block as defined by the {CloseRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian  :little

          uint16  :fid,                label: 'FID'
          uint32  :last_time_modified, label: 'Last Time Modified', initial_value: 0xFFFFFFFF
        end

        # Represents the specific layout of the DataBlock for a {CloseRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

      end
    end
  end
end
