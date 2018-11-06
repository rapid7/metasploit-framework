module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_SESSION_SETUP Legacy Response Packet as defined in
      # [2.2.4.53.2 Response](https://msdn.microsoft.com/en-us/library/ee442143.aspx)
      class SessionSetupLegacyResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP

        # A SMB1 Parameter Block as defined by the {SessionSetupResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block   :andx_block
          uint16        :action,       label: 'Action'
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          string      :pad,            label: 'Padding', length: 0
          stringz     :native_os,      label: 'Native OS'
          stringz     :native_lan_man, label: 'Native LAN Manager'
          stringz     :primary_domain, label: 'Primary Domain'
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
